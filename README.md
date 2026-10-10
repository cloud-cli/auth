# Auth

## Introduction

Auth is a self-hosted authentication and OpenID Connect (OIDC) provider for browser, native, and server-side applications. It provides Google sign-in, WebAuthn passkeys/security keys, recovery codes, QR-approved phone sign-in, sessions, OIDC, and scoped API tokens.

The project includes three integration modules for different application architectures:

- [`/index.mjs`](#integrate-a-browser-app-with-indexmjs): the browser client for applications that can navigate to Auth for sign-in.
- [`/oidc.mjs`](#restore-an-rp-session-from-an-spa-with-oidcmjs): popup helpers for restoring an application's own session without navigating the opener.
- [`/node.mjs`](#integrate-a-nodejs-service-with-nodemjs): a dependency-free Node.js client for server-side OIDC and shared-session helpers.

The built-in dashboard and login pages are served by Auth. The OpenAPI 3.1 reference is served at [`/api`](#http-api-and-oidc-reference).

## On this page

- [Tutorials](#tutorials): deploy Auth and choose an integration module.
- [How-to guides](#how-to-guides): configure OIDC, tokens, sessions, passkeys, and operations.
- [Concepts and operational guidance](#concepts-and-operational-guidance): understand sessions, authentication, and scaling constraints.
- [Reference](#reference): environment variables, HTTP APIs, and OIDC behavior.
- [Troubleshooting](#troubleshooting): diagnose common configuration and sign-in failures.

## Tutorials

### Getting started with Docker

This walkthrough assumes you have:

1. A public HTTPS hostname, such as `auth.example.com`, routed through a TLS-terminating reverse proxy to the container.
2. A database module URL for `DATABASE_URL`. The module must be reachable by the Auth container, export `getDb()`, and return an adapter with `all(sql, params)`, `get(sql, params)`, `run(sql, params)`, and `exec(sql)` methods. Auth runs its schema migrations at startup.
3. Google OAuth credentials for normal first-user onboarding. Google can be omitted only when accounts and another initial sign-in method are provisioned separately.

#### Generate secrets

Generate a strong, unique session secret:

```sh
openssl rand -hex 32
```

For OIDC signing and browser-issued access tokens, generate an RSA private key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
```

To enable persistent signing-key storage and dashboard rotation, also generate a 32-byte encryption key as 64 hexadecimal characters:

```sh
openssl rand -hex 32 > jwt-key-encryption.key
chmod 600 jwt-private.pem jwt-key-encryption.key
```

Keep these values in your deployment's secret manager. Do not commit them or paste them into a public issue. Mount the two JWT files read-only in production rather than putting private-key material in the Docker command line.

#### Configure Google sign-in

In the [Google API Console](https://console.cloud.google.com/apis/credentials), create an OAuth client for a web application and register:

- Authorized JavaScript origin: `https://auth.example.com`
- Authorized redirect URI: `https://auth.example.com/auth/google/callback`

Set the resulting client ID and secret as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

#### Start the container

Set `DATABASE_URL` to your database module URL and provide the generated session secret. The image listens on `PORT`:

```sh
export DATABASE_URL='https://db.example.com/auth-module.mjs'
export SESSION_SECRET="$(openssl rand -hex 32)"

# Supply these through your secret manager in production.
export GOOGLE_CLIENT_ID='your-google-client-id'
export GOOGLE_CLIENT_SECRET='your-google-client-secret'

docker run --name auth --detach \
  --publish 3000:3000 \
  --env PORT=3000 \
  --env AUTH_DOMAIN=https://auth.example.com \
  --env SESSION_DOMAIN=example.com \
  --env SESSION_COOKIE_SECURE=true \
  --env SESSION_SECRET \
  --env DATABASE_URL \
  --env GOOGLE_CLIENT_ID \
  --env GOOGLE_CLIENT_SECRET \
  --mount type=bind,src="$PWD/jwt-private.pem",dst=/run/secrets/jwt-private.pem,readonly \
  --mount type=bind,src="$PWD/jwt-key-encryption.key",dst=/run/secrets/jwt-key-encryption.key,readonly \
  --env JWT_PRIVATE_KEY_FILE=/run/secrets/jwt-private.pem \
  --env JWT_KEY_ENCRYPTION_KEY_FILE=/run/secrets/jwt-key-encryption.key \
  --env JWT_KEY_ID=auth-1 \
  ghcr.io/cloud-cli/auth:latest
```

`SESSION_DOMAIN=example.com` shares the Auth session cookie across `auth.example.com` and sibling subdomains. Omit `SESSION_DOMAIN` when the cookie should only be sent to the Auth hostname. Do not include a scheme or port in this value.

The container must be reachable only through HTTPS in production. Configure your reverse proxy to forward the original host and protocol and to route the Google callback path unchanged. The app applies database migrations during startup; ensure the database adapter and schema permissions allow that.

#### Configure JWT signing (optional)

The private-key mount above enables signed OIDC tokens and browser-issued access tokens. The encryption-key mount enables the dashboard to persist and rotate signing keys. `JWT_KEY_ID` is optional and defaults to `auth-1`; `JWT_TTL_SECONDS` defaults to 300 seconds and accepts values from 60 to 900.

For browser-issued tokens, also set `JWT_AUDIENCES` to the exact audience identifiers your resource APIs accept, and set `AUTH_ALLOWED_ORIGINS` to the browser application origins that may request them. OIDC clients managed through `/oidc` use their client IDs as token audiences and do not need to be listed in `JWT_AUDIENCES`.

#### Verify the deployment

- `GET https://auth.example.com/` should show the Auth landing page.
- `GET https://auth.example.com/.well-known/openid-configuration` should return OIDC metadata whose `issuer` is exactly `AUTH_DOMAIN` without a trailing slash.
- `GET https://auth.example.com/api` should return the API specification.
- Sign in, then visit `/me`; it should show the authenticated profile.

The first administrator account must be provisioned through your trusted deployment/database bootstrap process. Ordinary Google sign-ins create regular users; the service does not promote the first user automatically. A typical bootstrap is: sign in as the intended administrator, read that account's `user_id` from its authenticated profile, then use your database administrator tooling to run `UPDATE auth_user SET role = 'admin' WHERE user_id = ?` with that exact ID. Do not expose a public endpoint for this promotion.

### Integrate a browser app with `/index.mjs`

Use this module when a full-page navigation to Auth is acceptable. Auth serves the module from your Auth origin and the module uses the current Auth provider URL automatically.

```html
<script type="module">
  import * as auth from 'https://auth.example.com/index.mjs';

  document.querySelector('#sign-in').addEventListener('click', () => auth.signIn(false));
  document.querySelector('#sign-out').addEventListener('click', () => auth.signOut());

  auth.events.addEventListener('state', ({ detail: profile }) => {
    document.querySelector('#user').textContent = profile?.displayName ?? 'Signed out';
  });

  const profile = await auth.getProfile();
  console.log(profile);
</script>
```

`signIn(false)` navigates the current page to Auth and returns to the app after sign-in. `signIn(true)` opens a popup instead. For popup completion, Auth must be able to communicate with the opener; configure the exact relying-party origin in `EMBED_ALLOWED_ORIGINS`.

The module exports `signIn`, `signOut`, `getProfile`, `isAuthenticated`, `getAccessToken`, `authFetch`, property helpers (`getProperties`, `getProperty`, `setProperty`, `deleteProperty`), namespace variants, and an `events` event target. `getAccessToken(audience)` obtains and caches a short-lived JWT in memory. Use `authFetch(url, init, { audience })` to attach it to a resource request.

For cross-origin credentialed requests, configure the app origin in `AUTH_ALLOWED_ORIGINS`. For the module's embedded compatibility channel, configure it in `EMBED_ALLOWED_ORIGINS` as well. These are comma-separated origins, not paths. Do not forward Auth cookies to unrelated domains; use OIDC there.

### Restore an RP session from an SPA with `/oidc.mjs`

`/oidc.mjs` has one job: keep the SPA open while an RP-owned OIDC authorization flow runs in a popup and restores the RP's own session. It does not monitor Auth sessions, acquire tokens, or silently renew anything. The popup still performs the normal authorization-code/PKCE roundtrip.

Open the popup directly from a user gesture:

```js
import { openLoginPopup } from 'https://auth.example.com/oidc.mjs';

const popupLogin = {
  loginUrl: 'https://app.example.com/auth/login',
  completionOrigin: 'https://app.example.com',
  allowedOrigins: ['https://app.example.com'],
};

retryButton.addEventListener('click', async () => {
  try {
    await openLoginPopup(popupLogin);
    const response = await makeOriginalRequest(); // Recreate and retry at most once.
    renderResult(response);
  } catch (error) {
    renderRecoveryError(error);
  }
});
```

`openLoginPopup` creates a cryptographically random one-time nonce, appends it as the `oidc_popup_nonce` query parameter, opens the login URL, and returns a promise. It resolves only after the RP completion page confirms its session and sends a valid completion message. `loginUrl` may also be a builder function receiving `{ nonce }`. `allowedOrigins` must list the exact HTTPS origins for both the login URL and `completionOrigin` (localhost is allowed for development).

#### Carry the popup nonce through the RP's OIDC flow

The identity provider will not automatically preserve query parameters from the RP's login URL. The RP login handler must:

1. Read the `oidc_popup_nonce` parameter added by the helper.
2. Store it in the same short-lived, server-side transaction as the RP's OIDC `state`, `nonce`, and PKCE verifier.
3. On callback, look up that transaction by the returned `state`, validate `state` and the OIDC nonce, exchange the code, and establish the RP's session.
4. Render the popup completion page with the saved popup nonce from that validated transaction. Do not trust a nonce copied from an arbitrary callback query parameter.

This is the handoff contract between the opener helper and the RP. It binds the popup response to the active attempt without relying on the identity provider to echo RP-specific query parameters.

#### Confirm the RP session and complete the popup

On the RP-origin completion page, call `completePopupLogin` only after the server has established the RP session. Provide the popup nonce from the validated transaction, the fixed SPA opener origin, and an RP-owned endpoint that returns 2xx for an active session and 401 when no session exists:

```js
import { completePopupLogin } from 'https://auth.example.com/oidc.mjs';

await completePopupLogin({
  nonce: serverRenderedPopupNonce,
  openerOrigin: 'https://spa.example.com',
  allowedOpenerOrigins: ['https://spa.example.com'],
  completionOrigin: 'https://app.example.com',
  rpSessionCheck: '/api/session',
});
```

The completion helper checks that the current page is on `completionOrigin`, verifies `openerOrigin` against the configured allowlist, and checks the RP session in the popup context. It then posts `{ type: 'oidc:login-complete', nonce, status: 'complete' }` to that exact origin and closes the popup. If the session is not established, it sends a failure status and closes instead. The message contains no cookies, tokens, or profile data. Exported `POPUP_NONCE_PARAM` and `POPUP_MESSAGE_TYPE` constants define the wire names.

The opener accepts completion only when the message has the configured origin, comes from the popup it opened, and contains the expected type and nonce. Blocked popups, closed popups, timeout, RP login failure, and an unestablished RP session reject the promise with an error `code`; listeners and timers are cleaned up on every completion path. Do not automatically loop on 401s. Retry only once, after successful popup recovery, and only if the original request can be safely recreated; use an idempotency key or ask before replaying mutations.

The RP session check happens in the popup at the RP origin. This avoids depending on the SPA being able to read Auth cookies as third-party cookies. The browser still has to allow the normal top-level OIDC redirects and the RP's own session cookie. Avoid opener-isolating policies that sever `window.opener` for this popup flow, or configure a compatible policy and test it in target browsers.

### Integrate a Node.js service with `/node.mjs`

Use `/node.mjs` from a backend or a Node.js HTTP server. It has no npm dependency on Auth: the example below fetches the published module and imports it from a `data:` URL.

Register a confidential OIDC client in `/oidc` for a server-side application. Its callback URI must exactly match the URI registered with Auth. Keep its client secret on the server.

#### Complete minimal HTTP server example

This standalone example shows the complete redirect/callback/session flow using only Node.js built-ins and `/node.mjs`. The `Map` stores are for a single-process demonstration only; replace them with a persistent, expiring store in production.

```js
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const issuer = 'https://auth.example.com';
const appOrigin = 'https://inventory.example.com';
const redirectUri = `${appOrigin}/auth/callback`;
const source = await (await fetch(`${issuer}/node.mjs`)).text();
const { createAuthClient } = await import(`data:text/javascript,${encodeURIComponent(source)}`);
const auth = createAuthClient({
  issuer,
  clientId: 'inventory',
  clientSecret: process.env.AUTH_CLIENT_SECRET,
});

const loginTransactions = new Map(); // Use a shared store with a short TTL in production.
const appSessions = new Map(); // Use a persistent session store in production.

function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function sameValue(left, right) {
  const a = Buffer.from(left || '');
  const b = Buffer.from(right || '');
  return a.length === b.length && timingSafeEqual(a, b);
}

function redirect(response, location) {
  response.writeHead(302, { Location: location }).end();
}

createServer(async (request, response) => {
  const url = new URL(request.url, appOrigin);
  const cookies = auth.getCookies(request);

  if (url.pathname === '/login') {
    const loginId = randomBytes(32).toString('base64url');
    const login = auth.createAuthorizationRequest({ redirectUri });
    loginTransactions.set(loginId, { ...login, expiresAt: Date.now() + 5 * 60_000 });
    response.setHeader('Set-Cookie', setCookie('inventory.login', loginId, 300));
    return redirect(response, login.url);
  }

  if (url.pathname === '/auth/callback') {
    const loginId = cookies['inventory.login'];
    const login = loginTransactions.get(loginId);
    loginTransactions.delete(loginId);
    const clearLoginCookie = 'inventory.login=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
    if (!login || login.expiresAt < Date.now() || !sameValue(url.searchParams.get('state'), login.state)) {
      response.writeHead(400, { 'Set-Cookie': clearLoginCookie }).end('Invalid or expired login state');
      return;
    }

    try {
      const tokens = await auth.exchangeCode({
        code: url.searchParams.get('code') || '',
        codeVerifier: login.codeVerifier,
        redirectUri,
        clientSecret: process.env.AUTH_CLIENT_SECRET,
      });
      const claims = await auth.verifyToken(tokens.id_token);
      if (!sameValue(claims.nonce, login.nonce)) throw new Error('Invalid OIDC nonce');
      const user = await auth.getUserInfo(tokens.access_token);
      const sessionId = randomBytes(32).toString('base64url');
      appSessions.set(sessionId, user);
      response.setHeader('Set-Cookie', [clearLoginCookie, setCookie('inventory.sid', sessionId, 7 * 86400)]);
      return redirect(response, '/');
    } catch {
      response.writeHead(401, { 'Set-Cookie': clearLoginCookie }).end('Sign-in failed');
      return;
    }
  }

  if (url.pathname === '/') {
    const user = appSessions.get(cookies['inventory.sid']);
    if (!user) return redirect(response, '/login');
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end(`Hello, ${user.name}`);
    return;
  }

  response.writeHead(404).end('Not found');
}).listen(3000);
```

Persist login transactions and relying-party sessions in production; do not use in-memory maps across restarts or replicas. The callback binds `state` to the browser with a short-lived HTTP-only cookie and validates both `state` and the ID Token `nonce`. Keep the OIDC client secret in a server-side secret manager.

The module also exports `getProfile` (`getSessionProfile` is an alias), `getProperty`, `setProperty`, `deleteProperty` (`removeProperty` is an alias), `isSessionAuthenticated`, and `requireSession`. These helpers forward the Auth `connect.sid` cookie from the incoming request and are intended only for sibling subdomains that share `SESSION_DOMAIN`. They cannot authenticate a request from an unrelated domain. `getUserInfo(token)` fetches the OIDC UserInfo document, `introspectToken(token)` validates an opaque API token, `mintApiToken(...)` issues a downstream token with a fixed-purpose Auth API token, and `revokeApiToken(token)` uses the registered OIDC client credentials.

See [Share a session across sibling subdomains](#share-a-session-across-sibling-subdomains), [Store user properties](#store-user-properties), and [Issue and validate API tokens](#issue-and-validate-api-tokens) for these workflows.

## How-to guides

### Register an OIDC client

1. Sign in with an administrator account and open `/me#oidc` (or `/oidc`).
2. Choose a **confidential client** for a server-side app. Auth generates a secret and shows it once. Choose a **public client** for a native/mobile app; public clients have no secret and must use PKCE.
3. Register every callback URI exactly as the app will send it. Web redirects must use HTTPS, except loopback development URLs. Public native clients may use a reverse-domain private-use callback scheme.
4. Add the app's allowed downstream API scopes. These are separate from OIDC `openid`, `profile`, and `email` scopes.
5. If the app uses RP-initiated logout, register its exact post-logout redirect URI too.

Authorization uses the authorization-code flow with PKCE S256. The `state` and `nonce` values must be unpredictable and validated by the client. For compatibility, an omitted or blank OIDC `scope` defaults to `openid`; otherwise only `openid`, `profile`, and `email` are accepted. Profile and email claims are returned only when their scopes are requested. The ID Token and UserInfo `sub` values are the same stable account ID; `preferred_username` is optional and user-chosen.

Public dynamic client registration is not enabled. Client creation and management require an administrator. Confidential client secrets are stored hashed and cannot be retrieved after creation; regenerate a secret if it is lost.

For native applications, use the system browser or Android Custom Tabs—not an embedded web view—and a maintained OIDC library such as AppAuth for Android. Register the exact callback scheme in both the app and Auth. Use a cryptographically random `state` and `nonce` and validate both on return.

### Configure OIDC logout

Auth advertises RP-initiated logout at `/logout`. Redirect to it with `client_id`, the current `id_token_hint`, the exact registered `post_logout_redirect_uri`, and an unpredictable `state`. Auth validates the token and redirect before ending its browser session and returning the browser to the RP. The RP should validate the returned `state`.

### Issue and validate API tokens

Auth supports two different opaque token types. Do not confuse them:

- **API tokens** are user-subject tokens issued for an OIDC application's configured downstream scopes. An authenticated user can create/revoke them from `/me#oidc`. Tokens are shown once, stored hashed, expire after one year, and can be revoked.
- **Auth API tokens** are fixed-purpose, client-subject credentials for backend automation. An administrator creates them under **Keys & tokens** (`/me#auth-api-tokens`). They carry only the `auth:tokens:write` permission and can mint downstream API tokens for their own registered client; they cannot administer users, passkeys, or OIDC clients.

To mint a downstream token from a backend, create an Auth API token for the registered client and call:

```http
POST /api/v1/api-tokens/{clientId}/issue
Authorization: Bearer <auth-api-token>
Content-Type: application/json

{"label":"storage limits","scopes":["storage:limits"]}
```

The requested scopes must be configured for that client. Store the Auth API token in a server-side secret manager and revoke it from the dashboard if compromised. The Node module's `mintApiToken({ label, scopes })` performs this operation when `authApiToken` is provided to `createAuthClient`.

Resource APIs validate downstream opaque tokens with `POST /oauth/introspect`, using the registered OIDC client's HTTP Basic credentials. Active responses follow OAuth 2.0 Token Introspection and include `active`, `client_id`, `sub`, `scope`, `iat`, and `exp`; responses are marked `Cache-Control: no-store` and include `X-Token-Expires-At` metadata.

Registered OAuth clients may revoke opaque tokens with `POST /api/v1/revoke`, HTTP Basic client credentials, and a form-encoded `token`. The endpoint follows RFC 7009 and returns success for unknown tokens.

#### Configure downstream scopes

Add only the downstream API scopes a client needs in its OIDC client settings. Scope names are application-defined. A user's API token can contain only scopes configured for that client; adding or removing a client scope does not turn an Auth API token into a general-purpose credential.

#### Rotate JWT signing keys

Administrators can rotate signing keys from **Keys & tokens** on the dashboard. Rotation requires `JWT_KEY_ENCRYPTION_KEY_FILE` to point to a file containing a valid 32-byte key encoded as 64 hexadecimal characters. Auth retains retiring public keys long enough to validate tokens signed with them. The current key set is published at `/.well-known/jwks.json` and managed keys are listed at `GET /api/v1/keys`.

### Request a browser access token

`POST /api/v1/session/token` exchanges the user's Auth browser session for a short-lived RS256 JWT. The JSON body must include an audience listed in `JWT_AUDIENCES`, and browser requests must originate from an origin in `AUTH_ALLOWED_ORIGINS`. The endpoint requires JWT signing configuration. Public verification keys are served at `/.well-known/jwks.json`.

The browser modules cache short-lived access tokens in memory. Resource APIs should validate them against Auth's JWKS and check issuer, audience, expiry, and signature. OIDC access tokens use the OIDC client ID as their audience and do not require that ID in `JWT_AUDIENCES`.

### Share a session across sibling subdomains

Set `SESSION_DOMAIN` to a parent domain such as `example.com` when Auth and a relying party run on sibling subdomains. The browser will send the Auth `connect.sid` cookie to both hosts. Set `AUTH_ALLOWED_ORIGINS` to relying-party origins that make credentialed browser calls to Auth.

Do not forward the Auth cookie to an unrelated domain. For unrelated sites, use OIDC authorization-code flow and let the RP create its own session. Cookie helpers in `/node.mjs` only work when the incoming request already contains the shared Auth cookie.

### Store user properties

Use the dashboard or `/index.mjs` helpers to get, set, and delete per-user properties. The Node module exposes `getProperty(request, key)`, `setProperty(request, key, value)`, and `deleteProperty(request, key)` (also `removeProperty`). They forward the shared Auth session cookie to `/api/v1/properties`; `getProperty` returns `null` when there is no session or property.

### Set up passkeys and recovery

Users first sign in with Google or another available method, then register one or more passkeys/security keys from `/me` → **Passkeys**. Auth stores the credential public key, counter, device label, and revocation state; it never receives fingerprint data. Discoverable passkeys can sign in without an account identifier. Legacy non-discoverable U2F devices can sign in after entering the account email.

Users can remove a lost or retired credential from the same dashboard. To sign in with a recovery code, open `/recovery`, enter the account email and one unused code, and submit; the code is consumed on success.

Users can generate ten one-time recovery codes from `/me`. Codes are stored hashed, shown only once, and replaced (invalidating the old set) when regenerated. Keep at least one recovery method available, such as a separate security key, Google sign-in, or offline recovery codes. Store recovery codes offline, not in source control.

### Use QR phone approval

The login page offers **Approve on phone with QR**. The computer creates a short-lived, single-use login transaction and polls for approval. On the phone, open `/pwa/`, tap **Install Auth QR app** if offered, choose **Scan QR code**, scan the computer's code, and approve the displayed login. The phone does not copy its session cookie to the computer; the computer receives its own session. QR login does not use push notifications.

### Manage users and audit activity

Administrators can open **Users** from the dashboard to inspect accounts, set a preferred username, disable/enable accounts, block/unblock a sign-in identity, or delete an account. Auth prevents an administrator from disabling or deleting the final administrator. A disabled or blocked account's sessions are removed.

The authenticated audit view at `/me#activity` and `GET /api/v1/audit` records authentication outcomes and OIDC authorization/token-exchange events. It does not store bearer tokens, cookies, authorization codes, or client secrets. Audit records can be filtered by app and event.

Users may set a preferred username once. It is normalized to lowercase and must contain 1–30 letters, numbers, underscores, or hyphens; leading/trailing separators are not allowed. Administrators can update this value in the Users section.

### Run tests

Install dependencies and build:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm test:unit
pnpm lint
```

Integration tests use Playwright:

```sh
pnpm exec playwright install chromium
pnpm test:integration
```

Without `INTEGRATION_BASE_URL`, Playwright starts `pnpm start` on `http://127.0.0.1:3000`; configure the required database and application environment first. To test a running deployment, set `INTEGRATION_BASE_URL`. Tests that exercise test-key login require `AUTH_TEST_SECRET` or `AUTH_TEST_KEYS` in the test process.

## Concepts and operational guidance

### Authentication methods

Google OAuth, passkeys/security keys, recovery codes, and QR phone approval establish an Auth browser session. The OIDC provider then lets registered relying parties create their own sessions. An Auth session and an RP's application session are distinct: successful sign-in to one does not implicitly create the other.

### Sessions, cookies, and browser security

The server session is stored through the configured database adapter. `SESSION_SECRET` signs the session cookie. Use a stable secret across restarts and replicas; rotating it invalidates existing browser sessions. The default cookie name is `connect.sid`, path `/`, HTTP-only. `SESSION_DOMAIN` makes it available to sibling subdomains.

`AUTH_DOMAIN` must be the public HTTPS origin used by clients. HTTPS is required in production for WebAuthn, camera access, secure cookies, and the installable PWA. Configure a trusted reverse proxy and preserve the original host and protocol headers.

### Scaling and one-time state

Sessions, users, QR transactions, OIDC clients, tokens, and audit events use the database adapter. WebAuthn challenges and OIDC authorization codes are currently held in process memory; codes expire after one minute and WebAuthn challenges after two minutes. Use one Auth instance or session affinity for these flows until challenge/code storage supports shared, atomic one-time consumption.

### Built-in pages

Auth serves its own static UI pages and assets. Main routes include `/` (landing page), `/login`, `/me` (authenticated profile/dashboard), `/webauthn/login`, `/recovery`, `/qr-login`, and `/pwa/`. The PWA's service worker is `/ui/sw.js`; browser-only UI assets are under `/ui/`.

## Reference

### Environment variables

| Variable                      | Purpose                                                                                                                                         | Required / default                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `PORT`                        | HTTP port inside the container.                                                                                                                 | Required                                                |
| `DATABASE_URL`                | URL or importable module specifier for the database adapter. HTTP(S) URLs are fetched and imported as an ES module.                             | Required                                                |
| `AUTH_DOMAIN`                 | Public Auth origin, for example `https://auth.example.com` (no path). Used as OIDC issuer and WebAuthn origin.                                  | Required in production                                  |
| `SESSION_SECRET`              | Secret used to sign Express session cookies. Keep stable and private.                                                                           | Required                                                |
| `GOOGLE_CLIENT_ID`            | Google OAuth web client ID.                                                                                                                     | Required for Google sign-in                             |
| `GOOGLE_CLIENT_SECRET`        | Google OAuth web client secret.                                                                                                                 | Required for Google sign-in                             |
| `SESSION_DOMAIN`              | Parent cookie domain for sharing sessions across sibling subdomains, e.g. `example.com`.                                                        | Optional; host-only if unset                            |
| `SESSION_COOKIE_SAMESITE`     | Explicit session-cookie `SameSite` setting: `strict`, `lax`, or `none`. Leave unset for the default behavior.                                   | Optional                                                |
| `SESSION_COOKIE_SECURE`       | Any non-empty value enables the cookie's `Secure` flag; use `true` or leave unset (the string `false` still enables it).                        | Optional; off if unset                                  |
| `AUTH_NAME`                   | Human-readable WebAuthn relying-party name.                                                                                                     | Optional; `Auth`                                        |
| `AUTH_ALLOWED_ORIGINS`        | Comma-separated browser origins allowed for credentialed CORS and browser-issued JWT requests.                                                  | Optional; required for cross-origin browser APIs/tokens |
| `EMBED_ALLOWED_ORIGINS`       | Comma-separated relying-party origins/domains allowed to use the `/index.mjs` embedded message bridge.                                          | Optional; required for that bridge                      |
| `JWT_PRIVATE_KEY`             | PKCS#8 PEM private key used for RS256 JWT signing. Literal `\\n` sequences are converted to newlines.                                           | Optional; required for token signing                    |
| `JWT_PRIVATE_KEY_FILE`        | Path to a PEM private key. Takes precedence over `JWT_PRIVATE_KEY`.                                                                             | Optional                                                |
| `JWT_KEY_ENCRYPTION_KEY_FILE` | Path to a file containing a 32-byte key encoded as 64 hex characters; encrypts signing keys persisted in the database and enables key rotation. | Optional; required for managed key rotation             |
| `JWT_AUDIENCES`               | Comma-separated audiences allowed for `/api/v1/session/token`.                                                                                  | Optional; required for browser-issued JWTs              |
| `JWT_KEY_ID`                  | Initial/configured JWT key ID.                                                                                                                  | Optional; `auth-1`                                      |
| `JWT_TTL_SECONDS`             | JWT lifetime in seconds; valid range 60–900.                                                                                                    | Optional; `300`                                         |
| `QR_LOGIN_TTL_SECONDS`        | QR login transaction lifetime in seconds; valid range 60–600. Invalid values fall back to `300`.                                                | Optional; `300`                                         |
| `AUTH_TEST_KEYS`              | Comma-separated test keys that enable the test-login bypass. Test users are administrators.                                                     | Optional; test deployments only                         |
| `AUTH_TEST_SECRET`            | Backwards-compatible single-key alias for test login.                                                                                           | Optional; test deployments only                         |
| `DEBUG`                       | Enables the application's debug logger.                                                                                                         | Optional                                                |

Treat all secret values as credentials. Do not enable test-login variables on a production deployment.

### HTTP API and OIDC reference

The complete OpenAPI 3.1 document, schemas, and authentication requirements are at `GET /api`. Non-standard application APIs use `/api/v1/`; standard OIDC endpoints retain their standard paths.

Useful endpoints:

| Endpoint                                                              | Purpose                                             |
| --------------------------------------------------------------------- | --------------------------------------------------- |
| `GET /.well-known/openid-configuration`                               | OIDC provider metadata                              |
| `GET /.well-known/jwks.json`                                          | Public signing keys                                 |
| `GET /authorize`                                                      | OIDC authorization-code request                     |
| `POST /token`                                                         | Exchange an authorization code for tokens           |
| `GET /userinfo`                                                       | OIDC UserInfo for a valid access token              |
| `GET /logout`                                                         | RP-initiated logout                                 |
| `POST /oauth/introspect`                                              | Validate opaque API tokens using client credentials |
| `POST /api/v1/revoke`                                                 | Revoke opaque API tokens using client credentials   |
| `GET`, `HEAD`, `DELETE /api/v1/profile`                               | Read, check, or delete the current browser session  |
| `GET`, `PUT`, `DELETE /api/v1/properties...`                          | Read and manage user properties                     |
| `POST /api/v1/session/token`                                          | Exchange a browser session for a short-lived JWT    |
| `GET /api/v1/oidc/clients` and related routes                         | Administrator client management                     |
| `/api/v1/api-tokens/...` and `/api/v1/auth-api-tokens/...`            | Manage downstream and fixed-purpose API tokens      |
| `/api/v1/webauthn/...`, `/api/v1/recovery...`, `/api/v1/qr-login/...` | Passkey, recovery, and QR sign-in operations        |
| `/api/v1/admin/users...`                                              | Administrator user management                       |
| `/api/v1/audit`                                                       | Authenticated audit history                         |

### OAuth and OIDC behavior

- Authorization Code flow with PKCE S256 is supported.
- Supported OIDC scopes are `openid`, `profile`, and `email`; `openid` is the default when scope is omitted or blank.
- Confidential clients authenticate with client credentials at `/token`; public clients have no secret and rely on PKCE.
- Redirect URI matching is exact. Web redirects require HTTPS, except loopback development URIs. Native private-use callback schemes are allowed for public clients.
- Access tokens are signed with RS256. The provider metadata advertises only the supported response types, scopes, and authentication methods.
- Client credentials, API tokens, and session cookies are secrets; never expose them in browser logs, URLs, or source control.

### Integration module summary

| Module       | Runtime     | Sign-in model                                         | Main uses                                                                                         |
| ------------ | ----------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `/index.mjs` | Browser     | Full-page navigation or popup compatibility flow      | Profile, session checks, properties, cached JWTs, authenticated fetch                             |
| `/oidc.mjs`  | Browser SPA | RP-owned OIDC popup flow without replacing the opener | Nonce-bound completion, RP session confirmation, bounded recovery                                 |
| `/node.mjs`  | Node.js     | Backend-managed OIDC authorization-code flow          | PKCE, token exchange/verification, UserInfo, introspection, token issuance, shared-cookie helpers |

All three modules are served directly by the Auth origin and can be imported without installing an Auth-specific npm package.

## Troubleshooting

### The container exits or does not listen

- Confirm `PORT` is set to a valid number and the container port is published/routed correctly.
- Confirm `DATABASE_URL` is set, reachable from the container, and returns a valid ES module. Startup runs migrations and fails if the adapter cannot be loaded or used.
- If `AUTH_DOMAIN` is missing or malformed, Google callback URL construction, issuer metadata, WebAuthn, and QR login can fail. Set the exact public origin, including `https://`, without a path or trailing slash.
- Check startup logs for migration/schema-permission errors and database adapter failures.

### Google sign-in fails or returns to the login page

- Verify both Google credentials are set and belong to the same OAuth web client.
- The authorized origin must equal `AUTH_DOMAIN`; the redirect URI must exactly equal `${AUTH_DOMAIN}/auth/google/callback`.
- Ensure the reverse proxy forwards HTTPS and the public host to Auth and does not rewrite the callback path.

### The browser keeps showing the login page after a successful sign-in

- Inspect the browser's cookie storage for duplicate `connect.sid` cookies and ensure the browser sends the session cookie to the Auth hostname. Clear site data if duplicate host-only/domain cookies predate a `SESSION_DOMAIN` change.
- `SESSION_DOMAIN` must be only a domain name and should be the common parent for Auth and the relying party. A wrong domain prevents the browser from sending the cookie.
- Keep `SESSION_SECRET` stable across replicas and restarts. Changing it invalidates existing cookies.
- Check that the session database is reachable and shared by the Auth instance handling sign-in and the subsequent request.

### Cross-origin browser calls fail

- Put the exact origin (`scheme://host[:port]`, no path) in `AUTH_ALLOWED_ORIGINS`; include all relying-party origins as comma-separated values.
- For `/index.mjs` popup compatibility messaging, also add the relying-party origin/domain to `EMBED_ALLOWED_ORIGINS`.
- Use `credentials: 'include'` for browser fetches that rely on the Auth session. The browser will reject credentialed CORS responses with wildcard origins.
- For truly cross-site browser requests, cookies need `SESSION_COOKIE_SAMESITE=none` and `SESSION_COOKIE_SECURE=true`; browsers may still block third-party cookies. For unrelated domains, use OIDC and an RP-owned session instead of sharing the Auth cookie.

### JWT or token requests return configuration errors

- `JWT signing is not configured` means the RSA private key is absent, unreadable, malformed, or `AUTH_DOMAIN` is missing.
- `JWT_KEY_ENCRYPTION_KEY_FILE is not configured` means key persistence/rotation was requested without a readable 32-byte hex key file. Generate it with `openssl rand -hex 32`.
- A browser `/api/v1/session/token` request must use an audience in `JWT_AUDIENCES` and originate from an allowed `AUTH_ALLOWED_ORIGINS` origin.
- Check `JWT_TTL_SECONDS` is an integer from 60 through 900. OIDC managed-client audiences do not use `JWT_AUDIENCES`.

### Passkey, camera, or QR features do not work

- Use HTTPS in production. WebAuthn and camera permissions require a secure context (localhost is allowed for development).
- Set `AUTH_DOMAIN` to the browser-visible origin; it determines the WebAuthn RP ID and expected origin.
- Check `QR_LOGIN_TTL_SECONDS` is between 60 and 600. Invalid values use the 300-second default.
- WebAuthn challenges and OIDC authorization codes are process-local; a request routed to another instance may fail. Use one instance or session affinity for these flows.

### OIDC callback or logout is rejected

- Register the exact callback and post-logout URIs, including scheme, host, path, and port.
- Confirm `client_id`, client type, and confidential client secret match registration. Public clients must not send a client secret.
- Use PKCE S256 and verify the `state` and `nonce` values in the RP callback. Ensure `redirect_uri` is byte-for-byte the registered value.
- OIDC `/token` requires JWT signing configuration. Check provider metadata at `/.well-known/openid-configuration` and compare its issuer with the configured client issuer.
