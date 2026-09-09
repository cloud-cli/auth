import express from 'express';
import { readFileSync } from 'fs';
import { findByEmail, findByUserId, userAsJSON } from './user.js';
import { User, initStore } from './store.js';
import session from './session.js';
import log from './log.js';
import passport, { googleCallback } from './passport.js';
import { getProperties, removeProperty, getProperty, setProperty } from './properties.js';
import { accessTokenTtl, createAccessToken, getJwks, isAllowedAudience, isTokenServiceConfigured, verifyAccessToken } from './token.js';
import { createAuthorizationCode, exchangeAuthorizationCode, getClient, isOidcClient, tokenResponse } from './oidc.js';
import { authenticate, authenticationOptions, listAuthenticators, registrationOptions, registerAuthenticator, revokeAuthenticator } from './webauthn.js';
import { consumeRecoveryCode, replaceRecoveryCodes } from './recovery.js';
import { approveQrLogin, completeQrLogin, denyQrLogin, qrLoginDetails, qrLoginOrigin, qrLoginPage } from './qr-login.js';

const googleSvg = readFileSync('./assets/google.svg', 'utf8');
const esLibrary = readFileSync('./assets/index.mjs', 'utf8');
const esHelper = readFileSync('./assets/lib.mjs', 'utf8');
const nodeLibrary = readFileSync('./assets/node.mjs', 'utf8');
const openApiSpec = readFileSync('./assets/openapi.json', 'utf8');
const pwaHtml = readFileSync('./assets/pwa.html', 'utf8');
const pwaModule = readFileSync('./assets/pwa.mjs', 'utf8');
const pwaServiceWorker = readFileSync('./assets/pwa-sw.js', 'utf8');

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    return res.status(401).send(makeLoginPage());
  }

  next();
}

function protectedRouteWithRedirect(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    const returnUrl = req.get('referrer') || req.get('referer');
    res.set('Location', '/login?url=' + returnUrl);
    return res.status(401).send('');
  }

  next();
}

function logout(req, res) {
  req.logout((err) => (err ? res.status(500).send('') : res.status(202).send('OK')));
}

function bearerToken(req) {
  const authorization = req.get('authorization') || '';
  return authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : '';
}

async function tokenUser(req, res, next) {
  const token = bearerToken(req);
  const audience = req.get('x-auth-audience') || '';

  if (!token || !audience || (!isAllowedAudience(audience) && !isOidcClient(audience))) {
    return res.status(401).send('');
  }

  try {
    const { payload } = await verifyAccessToken(token, audience);
    if (!payload.sub) return res.status(401).send('');

    req.tokenUserId = payload.sub;
    next();
  } catch {
    res.status(401).send('');
  }
}

function sessionTokenCors(req, res, next) {
  const origin = req.get('origin');
  const allowedOrigins = new Set((process.env.AUTH_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean));

  if (!origin || !allowedOrigins.has(origin)) return res.status(403).send('');

  res.vary('Origin');
  res.set('Access-Control-Allow-Origin', origin);
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  next();
}

async function getProfile(req, res) {
  const user = await findByUserId(req.user?.id);

  if (user) {
    res.send(await makeProfile(user));
    return;
  }

  res.status(404).send('{}');
}

function makePage(title: string, page: string) {
  return [
    `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${title}</title>
      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.16/dist/tailwind.min.css" rel="stylesheet" />
      <script type="module">
      async function load() {
        globalThis.Auth = await import('/index.mjs');
      }
      load();
      </script>
  </head>
  <body>`,
    page,
    `</body>
  </html>`,
  ].join('');
}

function makeLoginPage(returnUrl = '/me') {
  return makePage(
    'Sign in to continue',
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center px-4">
      <div class="text-center p-4 bg-white rounded-lg shadow">
        <h1 class="text-2xl font-bold mb-6">Hello!</h1>
        <a href="/auth/google" class="bg-white border text-gray-800 px-4 py-2 rounded shadow flex items-center justify-center">
          ${googleSvg}
          Sign in with Google
        </a>
        <a href="/webauthn/login" class="block bg-gray-900 text-white px-4 py-2 rounded shadow mt-3">Sign in with a passkey</a>
        <a href="/qr-login?url=${encodeURIComponent(returnUrl)}" class="block border text-gray-800 px-4 py-2 rounded shadow mt-3">Approve on phone with QR</a>
        <a href="/recovery" class="block text-sm text-gray-600 mt-3">Use a recovery code</a>
      </div>
      <script>
      (function(){sessionStorage.url=[...new URLSearchParams(location.search)].find(p=>p[0]==="url")?.[1] || ''})();
      </script>`,
  );
}

function makePasskeyLoginPage() {
  return makePage(
    'Sign in with a passkey',
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center px-4">
      <div class="text-center p-4 bg-white rounded-lg shadow">
        <h1 class="text-2xl font-bold mb-6">Passkey sign-in</h1>
        <input id="account" class="border p-2 rounded mb-3" placeholder="Email (optional for phone passkeys)" autocomplete="username webauthn" />
        <button id="signin" class="bg-gray-900 text-white px-4 py-2 rounded shadow">Unlock with passkey</button>
        <p id="error" class="text-red-600 mt-4"></p>
      </div>
    </div>
    <script type="module">
      import { signInWithPasskey } from '/index.mjs';
      signin.onclick = async () => {
        try {
          await signInWithPasskey(account.value);
          location.href = '/me';
        } catch (error) {
          document.querySelector('#error').textContent = error.message;
        }
      };
      signin.click();
    </script>`,
  );
}

function makeRecoveryPage() {
  return makePage('Use a recovery code', `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center px-4"><form method="post" class="text-center p-4 bg-white rounded-lg shadow"><h1 class="text-2xl font-bold mb-6">Recovery sign-in</h1><input name="email" type="email" required placeholder="Email" class="border p-2 rounded block mb-2" /><input name="code" required placeholder="Recovery code" class="border p-2 rounded block mb-2" /><button class="bg-gray-900 text-white px-4 py-2 rounded shadow">Sign in</button></form></div>`);
}

function makeQrLoginPage(qr: string, pwaUrl: string, token: string) {
  return makePage('Approve on phone', `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center px-4"><div class="text-center p-4 bg-white rounded-lg shadow"><h1 class="text-2xl font-bold mb-4">Scan with your phone</h1><img src="${qr}" alt="QR code" width="320" height="320" /><p>Open the Auth app, scan this code, and approve the login.</p><p id="status">Waiting for approval...</p><p><a href="${pwaUrl}">Open Auth PWA</a></p></div></div><script>const token=${JSON.stringify(token)};const poll=async()=>{const r=await fetch('/qr-login/status?transaction='+encodeURIComponent(token),{credentials:'include'});if(r.ok){const x=await r.json();if(x.status==='approved'){location.href=x.returnUrl;return}if(x.status==='denied')document.querySelector('#status').textContent='Login denied.'}setTimeout(poll,1000)};poll();</script>`);
}

async function makeProfile(user: User) {
  const profile = JSON.stringify(user);
  const fields = ['userId', 'profileId', 'accessToken', 'refreshToken'] as Array<keyof User>;
  const fieldsText = fields
    .map((key) => ({ key, value: user[key] || '' }))
    .map(
      ({ key, value }) => `<div class="flex items-center font-mono border-b">
        <span class="w-1/3 p-1">${key}</span>
        <span class="w-2/3 truncate p-1" onclick="$event.target.classList.toggle('truncate')">${value}</span>
      </div>`,
    )
    .join('\n');

  const properties = await getProperties(user.userId);
  const propertiesText = properties
    .map(({ key, value }) => {
      return `<div class="flex items-center font-mono border-b">
      <span class="w-1/3 p-1">${key}</span>
      <span class="w-2/3 flex-1 text-red-500 p-1 truncate">${value}</span>
      <button class="flex-1" onclick="if(confirm('Sure?')){Auth.deleteProperty('${key}');$event.target.parentNode.remove();}">&times;</button>
    </div>`;
    })
    .join('\n');
  const authenticators = await listAuthenticators(user.userId);
  const authenticatorsText = authenticators
    .filter((authenticator) => !authenticator.revokedAt)
    .map((authenticator) => `<div class="flex items-center font-mono border-b"><span class="flex-1 p-1">${authenticator.label}</span><span class="flex-1 p-1 text-gray-400">${authenticator.lastUsedAt || 'never used'}</span><button class="p-1" onclick="Auth.revokePasskey('${authenticator.credentialId}').then(()=>location.reload())">Revoke</button></div>`)
    .join('\n');

  return makePage(
    'Profile',
    `<div class="hidden" id="r">Redirecting</div>
    <div class="bg-gray-100 h-screen w-screen flex items-center justify-center p-4 hidden" id="p">
      <div class="bg-white rounded-xl mx-auto p-8 border shadow-lg max-w-full md:max-w-5xl max-h-full overflow-auto">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block space-y-1">
            <div class="text-center py-4">Hello, ${user.name}!</div>
          </figcaption>
        </figure>
        <hr class="mt-4" />
        <button type="button" onclick="l()" class="block bg-white text-gray-800 p-2 text-sm rounded shadow border border-gray-200 mt-4 mx-auto">Logout</button>
        <hr class="mt-4" />
        <div class="text-sm text-gray-400 space-y-1">
          ${fieldsText}
          ${propertiesText}
          <div class="font-bold border-b mt-4 p-1">Passkeys</div>
          ${authenticatorsText || '<div class="p-1">No passkeys registered</div>'}
        </div>
        <div class="flex items-centers justify-center p-2">
          <button onclick="Auth.setProperty( prompt('Key', ''), prompt('Value', '') );window.location.relaod()">Add</button>
          <button class="ml-4" onclick="Auth.registerPasskey(prompt('Passkey name', 'My device')).then(()=>location.reload())">Add passkey</button>
          <button class="ml-4" onclick="Auth.generateRecoveryCodes().then(codes=>alert(codes.join('\\n')))" >New recovery codes</button>
        </div>
      </div>
    </div>
    <script>
    async function l(){await fetch('/',{method:'DELETE'});location.href='/login';}
    addEventListener('DOMContentLoaded',() => {
      const n = sessionStorage.url || '';
      if (n) {
        setTimeout(()=>location.href=n,1000);
        return window.r.classList.add('hidden');
      }

      window.p.classList.remove('hidden');
      (opener||window).postMessage({ event: 'signin', detail: ${profile} }, '*');
    });
    </script>`,
  );
}

async function makeEmbedPage(_req, res) {
  const allowedOrigins = (process.env.EMBED_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim());

  res.send(`<script type="module">
import { runCommand } from '/lib.mjs';
const allowedOrigins = ${JSON.stringify(allowedOrigins)};
window.addEventListener("message", async function (event) {
  if (!allowedOrigins.some(o => event.origin.endsWith(o))) {
    console.log('Origin not allowed: ' + event.origin, event);
    return;
  }

  runCommand(event);
}, false);
</script>`);
}

const googleScopes = {
  scope: ['profile', 'email'],
  failureRedirect: '/login',
  successRedirect: '/me',
};

const app = express();

app.set('trust proxy', 1);
app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.on('finish', () => {
    const date = new Date().toISOString().slice(0, 19);
    console.log(`[${date}] ${req.method} ${req.url} ${res.statusCode}`);
  });
  next();
});

app.get('/', protectedRouteWithRedirect, async (req, res) => {
  const user = await findByUserId(req.user?.id);
  if (user) {
    res.send(userAsJSON(user));
    return;
  }

  res.status(404).send('{}');
});
app.head('/', protectedRoute, (_req, res) => {
  res.status(204).send('');
});
app.delete('/', protectedRoute, logout);
app.get('/login', (req, res) => {
  res.send(makeLoginPage(typeof req.query.url === 'string' ? req.query.url : '/me'));
});
app.get('/webauthn/login', (_req, res) => {
  res.send(makePasskeyLoginPage());
});
app.get('/recovery', (_req, res) => res.send(makeRecoveryPage()));
app.post('/recovery', express.urlencoded({ extended: false }), async (req, res) => {
  const user = await consumeRecoveryCode(String(req.body?.email || ''), String(req.body?.code || ''));
  if (!user) return res.status(401).send('Invalid recovery code');
  req.login(userAsJSON(user), (error) => {
    if (error) return res.status(500).send('Could not create session');
    res.redirect('/me');
  });
});
app.get('/qr-login', async (req, res) => {
  const page = await qrLoginPage(req.sessionID, typeof req.query.url === 'string' ? req.query.url : '/me');
  res.send(makeQrLoginPage(page.qr, page.pwaUrl, page.token));
});
app.get('/qr-login/status', async (req, res) => {
  try {
    const token = typeof req.query.transaction === 'string' ? req.query.transaction : '';
    const transaction = qrLoginOrigin(token, req.sessionID);
    if (transaction.status !== 'approved') return res.json({ status: transaction.status });
    const completed = await completeQrLogin(token, req.sessionID);
    if (!completed) return res.status(401).json({ status: 'expired' });
    req.login(completed.user, (error) => {
      if (error) return res.status(500).json({ status: 'error' });
      res.json({ status: 'approved', returnUrl: completed.returnUrl });
    });
  } catch {
    res.status(410).json({ status: 'expired' });
  }
});
app.get('/qr-login/details', protectedRoute, (req, res) => {
  try {
    const token = typeof req.query.transaction === 'string' ? req.query.transaction : '';
    res.json(qrLoginDetails(token));
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/qr-login/approve', express.json(), protectedRoute, async (req, res) => {
  try {
    await approveQrLogin(String(req.body?.transaction || ''), req.user!.id);
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/qr-login/deny', express.json(), protectedRoute, (req, res) => {
  try {
    denyQrLogin(String(req.body?.transaction || ''));
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.get('/pwa/', (_req, res) => res.type('html').send(pwaHtml));
app.get('/pwa/pwa.mjs', (_req, res) => res.type('javascript').send(pwaModule));
app.get('/pwa/sw.js', (_req, res) => res.type('javascript').set('Service-Worker-Allowed', '/pwa/').send(pwaServiceWorker));
app.get('/pwa/manifest.webmanifest', (_req, res) => res.type('application/manifest+json').json({ name: 'Auth', short_name: 'Auth', start_url: '/pwa/', display: 'standalone', background_color: '#f3f4f6', theme_color: '#111827', scope: '/pwa/' }));
app.get('/webauthn/register/options', protectedRoute, async (req, res) => {
  res.json(await registrationOptions(req.user!.id));
});
app.post('/webauthn/register/verify', express.json(), protectedRoute, async (req, res) => {
  try {
    const authenticator = await registerAuthenticator(req.user!.id, req.body, typeof req.body?.label === 'string' ? req.body.label : 'Passkey');
    res.status(201).json({ credentialId: authenticator.credentialId, label: authenticator.label });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.get('/webauthn/authentication/options', async (req, res) => {
  const loginHint = typeof req.query.login_hint === 'string' ? req.query.login_hint : '';
  const user = loginHint ? (loginHint.includes('@') ? await findByEmail(loginHint) : await findByUserId(loginHint)) : null;
  res.json(await authenticationOptions(user?.userId));
});
app.post('/webauthn/authentication/verify', express.json(), async (req, res) => {
  try {
    const { userId } = await authenticate(req.body);
    const user = await findByUserId(userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.login(userAsJSON(user), (error) => {
      if (error) return res.status(500).json({ error: 'Could not create session' });
      res.status(204).send('');
    });
  } catch (error) {
    res.status(401).json({ error: String(error) });
  }
});
app.get('/webauthn/credentials', protectedRoute, async (req, res) => {
  const authenticators = await listAuthenticators(req.user!.id);
  res.json(authenticators.map(({ credentialId, label, transports, createdAt, lastUsedAt, revokedAt }) => ({ credentialId, label, transports, createdAt, lastUsedAt, revokedAt })));
});
app.post('/recovery-codes', express.json(), protectedRoute, async (req, res) => {
  const user = await findByUserId(req.user!.id);
  if (!user) return res.status(404).send('');
  res.json({ codes: await replaceRecoveryCodes(user) });
});
app.delete('/webauthn/credentials/:credentialId', protectedRoute, async (req, res) => {
  const revoked = await revokeAuthenticator(req.user!.id, req.params.credentialId);
  res.sendStatus(revoked ? 204 : 404);
});
app.get('/api', (_req, res) => {
  res.type('application/json').send(openApiSpec);
});
app.options('/session/token', sessionTokenCors, (_req, res) => res.sendStatus(204));
app.post('/session/token', express.json(), sessionTokenCors, protectedRoute, async (req, res) => {
  const audience = typeof req.body?.audience === 'string' ? req.body.audience : '';
  if (!isTokenServiceConfigured()) return res.status(503).send('JWT service is not configured');
  if (!isAllowedAudience(audience)) return res.status(400).send('Invalid audience');

  res.json({ access_token: await createAccessToken(req.user!.id, audience), token_type: 'Bearer', expires_in: accessTokenTtl() });
});
app.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  const clientId = typeof client_id === 'string' ? client_id : '';
  const redirectUri = typeof redirect_uri === 'string' ? redirect_uri : '';
  const client = getClient(clientId);

  if (response_type !== 'code' || !client || !client.redirectUris.includes(redirectUri) || typeof state !== 'string' || typeof code_challenge !== 'string' || code_challenge_method !== 'S256') {
    return res.status(400).send('Invalid authorization request');
  }
  if (!req.isAuthenticated?.() || !req.user?.id) {
    return res.redirect('/login?url=' + encodeURIComponent(req.originalUrl));
  }

  const code = createAuthorizationCode(client, redirectUri, req.user.id, code_challenge);
  const callback = new URL(redirectUri);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', state);
  res.redirect(String(callback));
});
app.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri, code_verifier } = req.body || {};
  if (grant_type !== 'authorization_code' || [code, client_id, client_secret, redirect_uri, code_verifier].some((value) => typeof value !== 'string')) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  if (!isTokenServiceConfigured()) return res.status(503).json({ error: 'temporarily_unavailable' });

  const authorizationCode = await exchangeAuthorizationCode({ code, clientId: client_id, clientSecret: client_secret, redirectUri: redirect_uri, codeVerifier: code_verifier });
  if (!authorizationCode) return res.status(400).json({ error: 'invalid_grant' });

  const user = await findByUserId(authorizationCode.userId);
  if (!user) return res.status(400).json({ error: 'invalid_grant' });

  res.json(await tokenResponse(user, client_id));
});
app.get('/.well-known/jwks.json', async (_req, res) => {
  const jwks = await getJwks();
  if (!jwks) return res.status(503).send('JWT service is not configured');

  res.set('Cache-Control', 'public, max-age=3600').json(jwks);
});
app.get('/userinfo', tokenUser, async (req, res) => {
  const user = await findByUserId(req.tokenUserId);
  if (!user) return res.status(404).send('{}');

  res.json(userAsJSON(user));
});
app.get('/embed', makeEmbedPage);
app.get('/me', protectedRoute, getProfile);
app.get('/auth/google', passport.authenticate('google', googleScopes));
app.get(googleCallback, passport.authenticate('google', googleScopes));

const serveEsModule = (source) => (req, res) => {
  console.log(req.headers);
  const host = req.headers['x-forwarded-host'] || req.headers['x-forwarded-for'] || 'localhost';
  const es = source.replace('__API_URL__', 'https://' + host);
  res.set('Content-Type', 'text/javascript').set('Access-Control-Allow-Origin', '*').send(es);
};

app.get('/auth.js', serveEsModule(esLibrary));
app.get('/index.js', serveEsModule(esLibrary));
app.get('/index.mjs', serveEsModule(esLibrary));
app.get('/node.mjs', serveEsModule(nodeLibrary));
app.get('/lib.mjs', serveEsModule(esHelper));

app.put('/properties', protectedRoute, async (req, res) => {
  const buffer = Buffer.concat(await req.toArray()).toString('utf8');

  try {
    const payload = JSON.parse(buffer);
    const { key, value } = payload;
    const property = await setProperty(req.user?.id, key, value);
    res.status(200).send(property);
  } catch (e) {
    log(e);
    res.status(500).send('');
  }
});

app.get('/properties', protectedRoute, async (req, res) => {
  try {
    const properties = await getProperties(req.user?.id);
    res.status(200).send(properties);
  } catch (e) {
    res.status(500).send('');
    console.error(e);
  }
});

app.delete('/properties/:key', protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user?.id;

  if (!key) {
    res.status(400).send('');
    return;
  }

  try {
    await removeProperty(userId, key);
    res.status(202).send('');
  } catch (e) {
    res.status(500).send('');
    console.error(e);
  }
});

app.get('/properties/:key', protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user?.id;

  if (!key) {
    res.status(400).send('');
    return;
  }

  const property = await getProperty(userId, key);
  if (property) {
    res.status(200).send(property);
    return;
  }

  res.status(404).send('');
});

const PORT = Number(process.env.PORT);
app.listen(PORT, async () => {
  await initStore();
  log('Auth is running on port ' + PORT);
});
