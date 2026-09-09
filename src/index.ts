import express from 'express';
import { readFileSync } from 'fs';
import { findByEmail, findByUserId, userAsJSON } from './user.js';
import { initStore } from './store.js';
import session from './session.js';
import log from './log.js';
import passport, { googleCallback } from './passport.js';
import { getProperties, removeProperty, getProperty, setProperty } from './properties.js';
import {
  accessTokenTtl,
  createAccessToken,
  getJwks,
  initializeSigningKeys,
  isAllowedAudience,
  isTokenServiceConfigured,
  listSigningKeys,
  rotateSigningKey,
  verifyAccessToken,
} from './token.js';
import { createAuthorizationCode, createManagedClient, exchangeAuthorizationCode, getClient, isOidcClient, listManagedClients, removeManagedClient, tokenResponse } from './oidc.js';
import {
  authenticate,
  authenticationOptions,
  listAuthenticators,
  registrationOptions,
  registerAuthenticator,
  revokeAuthenticator,
} from './webauthn.js';
import { consumeRecoveryCode, replaceRecoveryCodes } from './recovery.js';
import { getAuditEvents, recordAudit } from './audit.js';
import {
  approveQrLogin,
  completeQrLogin,
  denyQrLogin,
  qrLoginDetails,
  qrLoginOrigin,
  qrLoginPage,
} from './qr-login.js';

const esLibrary = readFileSync('./assets/index.mjs', 'utf8');
const dashboardLibrary = readFileSync('./assets/dashboard.mjs', 'utf8');
const esHelper = readFileSync('./assets/lib.mjs', 'utf8');
const nodeLibrary = readFileSync('./assets/node.mjs', 'utf8');
const openApiSpec = readFileSync('./assets/openapi.json', 'utf8');
const pwaServiceWorker = readFileSync('./assets/pwa-sw.js', 'utf8');
const uiAssets = Object.fromEntries(
  [
    'login.html',
    'landing.html',
    'auth-nav.html',
    'security.html',
    'properties.html',
    'activity.html',
    'oidc-apps.html',
    'keys.html',
    'passkey.html',
    'recovery.html',
    'profile.html',
    'qr-login.html',
    'pwa.html',
    'app.mjs',
    'pwa.mjs',
    'qr.css',
    'manifest.webmanifest',
    'auth-qr-icon.svg',
    'embed.html',
    'embed.mjs',
  ].map((name) => [name, readFileSync('./assets/ui/' + name, 'utf8')]),
);

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    return res.status(401).send('');
  }

  next();
}

function protectedPage(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    return res.redirect('/login?url=' + encodeURIComponent(req.originalUrl));
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

  if (!token || !audience || (!isAllowedAudience(audience) && !(await isOidcClient(audience)))) {
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
  const allowedOrigins = new Set(
    (process.env.AUTH_ALLOWED_ORIGINS || '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
  );

  if (!origin || !allowedOrigins.has(origin)) return res.status(403).send('');

  res.vary('Origin');
  res.set('Access-Control-Allow-Origin', origin);
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  next();
}

function browserCors(req, res, next) {
  const origin = req.get('origin');
  const configuredOrigins = [process.env.AUTH_ALLOWED_ORIGINS, process.env.EMBED_ALLOWED_ORIGINS]
    .flatMap((value) => (value || '').split(','))
    .map((value) => value.trim())
    .filter(Boolean);
  if (origin && isAllowedBrowserOrigin(origin, configuredOrigins)) {
    res.vary('Origin');
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  next();
}

function adminRoute(req, res, next) {
  if (!req.isAuthenticated?.() || !isOidcAdmin(req.user?.id)) return res.status(403).send('');
  next();
}

function isOidcAdmin(userId: string | undefined) {
  return Boolean(userId && (process.env.OIDC_ADMIN_USER_IDS || '').split(',').map((value) => value.trim()).includes(userId));
}

function isAllowedBrowserOrigin(origin: string, configuredOrigins: string[]) {
  try {
    const hostname = new URL(origin).hostname;
    return configuredOrigins.some((value) => {
      if (value === origin) return true;
      const domain = value.replace(/^https?:\/\//, '').replace(/^\./, '').split('/')[0];
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  } catch {
    return false;
  }
}

function serveUi(name: string) {
  return (_req, res) => {
    const source = name === 'profile.html'
      ? uiAssets[name].replace('"@li3/":"https://cdn.li3.dev/@li3/"', '"@li3/":"https://cdn.li3.dev/@li3/","@apphor/":"/"').replace('<link rel="component" href="/ui/oidc-apps.html">', '<link rel="component" href="/ui/oidc-apps.html"><link rel="component" href="/ui/keys.html">').replace('<template if="section === \'oidc\'"><dashboard-oidc></dashboard-oidc></template>', '<template if="section === \'oidc\'"><dashboard-oidc></dashboard-oidc></template><template if="section === \'keys\'"><signing-key-manager></signing-key-manager></template>')
      : uiAssets[name];
    res.type('html').send(source);
  };
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

app.get('/', serveUi('landing.html'));
app.get('/profile', browserCors, protectedRouteWithRedirect, async (req, res) => {
  const user = await findByUserId(req.user?.id);
  if (user) {
    res.send(userAsJSON(user));
    return;
  }

  res.status(404).send('{}');
});
app.head('/profile', browserCors, protectedRoute, (_req, res) => {
  res.status(204).send('');
});
app.delete('/profile', protectedRoute, logout);
app.get('/login', (req, res) => {
  const returnUrl = typeof req.query.url === 'string' ? req.query.url : '/me';
  if (req.isAuthenticated?.() && req.user?.id && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    return res.redirect(302, returnUrl);
  }
  serveUi('login.html')(req, res);
});
app.get('/webauthn/login', serveUi('passkey.html'));
app.get('/recovery', serveUi('recovery.html'));
app.get('/oidc', adminRoute, (_req, res) => res.redirect('/me#oidc'));
app.get('/oidc/access', protectedRoute, (req, res) => res.json({ admin: isOidcAdmin(req.user!.id) }));
app.get('/keys', adminRoute, async (_req, res) => res.json(await listSigningKeys()));
app.post('/keys/rotate', express.json(), adminRoute, async (_req, res) => {
  try { res.status(201).json(await rotateSigningKey()); } catch (error) { res.status(503).json({ error: String(error) }); }
});
app.get('/audit', protectedRoute, async (req, res) => res.json(await getAuditEvents(req.user!.id)));
app.post('/recovery', express.urlencoded({ extended: false }), async (req, res) => {
  const user = await consumeRecoveryCode(String(req.body?.email || ''), String(req.body?.code || ''));
  if (!user) {
    await recordAudit({ event: 'recovery-authentication', app: 'recovery-code', result: 'failure' });
    return res.status(401).send('Invalid recovery code');
  }
  await recordAudit({ userId: user.userId, event: 'recovery-authentication', app: 'recovery-code', result: 'success' });
  req.login(userAsJSON(user), (error) => {
    if (error) return res.status(500).send('Could not create session');
    res.redirect('/me');
  });
});
app.get('/qr-login/start', async (req, res) => {
  const page = await qrLoginPage(req.sessionID, typeof req.query.url === 'string' ? req.query.url : '/me');
  res.json(page);
});
app.get('/qr-login', serveUi('qr-login.html'));
app.get('/qr-login/status', async (req, res) => {
  try {
    const token = typeof req.query.transaction === 'string' ? req.query.transaction : '';
    const transaction = await qrLoginOrigin(token, req.sessionID);
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
app.get('/qr-login/details', protectedRoute, async (req, res) => {
  try {
    const token = typeof req.query.transaction === 'string' ? req.query.transaction : '';
    res.json(await qrLoginDetails(token));
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/qr-login/approve', express.json(), protectedRoute, async (req, res) => {
  try {
    await approveQrLogin(String(req.body?.transaction || ''), req.user!.id);
    await recordAudit({ userId: req.user!.id, event: 'qr-approval', app: 'QR login', result: 'success' });
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/qr-login/deny', express.json(), protectedRoute, async (req, res) => {
  try {
    await denyQrLogin(String(req.body?.transaction || ''));
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.get('/pwa/', serveUi('pwa.html'));
app.get('/pwa/sw.js', (_req, res) =>
  res.type('javascript').set('Service-Worker-Allowed', '/pwa/').send(pwaServiceWorker),
);
app.get('/pwa/manifest.webmanifest', (_req, res) =>
  res.type('application/manifest+json').send(uiAssets['manifest.webmanifest']),
);
app.get('/webauthn/register/options', protectedRoute, async (req, res) => {
  res.json(await registrationOptions(req.user!.id));
});
app.post('/webauthn/register/verify', express.json(), protectedRoute, async (req, res) => {
  try {
    const authenticator = await registerAuthenticator(
      req.user!.id,
      req.body,
      typeof req.body?.label === 'string' ? req.body.label : 'Passkey',
    );
    res.status(201).json({ credentialId: authenticator.credentialId, label: authenticator.label });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.get('/webauthn/authentication/options', async (req, res) => {
  const loginHint = typeof req.query.login_hint === 'string' ? req.query.login_hint : '';
  const user = loginHint
    ? loginHint.includes('@')
      ? await findByEmail(loginHint)
      : await findByUserId(loginHint)
    : null;
  res.json(await authenticationOptions(user?.userId));
});
app.post('/webauthn/authentication/verify', express.json(), async (req, res) => {
  try {
    const { userId } = await authenticate(req.body);
    const user = await findByUserId(userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    await recordAudit({ userId, event: 'passkey-authentication', app: 'WebAuthn', result: 'success' });
    req.login(userAsJSON(user), (error) => {
      if (error) return res.status(500).json({ error: 'Could not create session' });
      res.status(204).send('');
    });
  } catch (error) {
    await recordAudit({ event: 'passkey-authentication', app: 'WebAuthn', result: 'failure' });
    res.status(401).json({ error: String(error) });
  }
});
app.get('/webauthn/credentials', protectedRoute, async (req, res) => {
  const authenticators = await listAuthenticators(req.user!.id);
  res.json(
    authenticators.map(({ credentialId, label, transports, createdAt, lastUsedAt, revokedAt }) => ({
      credentialId,
      label,
      transports,
      createdAt,
      lastUsedAt,
      revokedAt,
    })),
  );
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
app.get('/api', (req, res) => {
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost || req.host;
  res.type('application/json').send(openApiSpec.replace('__HOSTNAME__', host));
});
app.get('/oidc/clients', adminRoute, async (_req, res) => res.json(await listManagedClients()));
app.post('/oidc/clients', express.json(), adminRoute, async (req, res) => {
  try {
    const result = await createManagedClient(String(req.body?.id || ''), Array.isArray(req.body?.redirectUris) ? req.body.redirectUris.filter((value) => typeof value === 'string') : []);
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.delete('/oidc/clients/:id', adminRoute, async (req, res) => res.sendStatus((await removeManagedClient(req.params.id)) ? 204 : 404));
app.options('/session/token', sessionTokenCors, (_req, res) => res.sendStatus(204));
app.post('/session/token', express.json(), sessionTokenCors, protectedRoute, async (req, res) => {
  const audience = typeof req.body?.audience === 'string' ? req.body.audience : '';
  if (!isTokenServiceConfigured()) return res.status(503).send('JWT service is not configured');
  if (!isAllowedAudience(audience)) return res.status(400).send('Invalid audience');

  res.json({
    access_token: await createAccessToken(req.user!.id, audience),
    token_type: 'Bearer',
    expires_in: accessTokenTtl(),
  });
});
app.get('/authorize', async (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  const clientId = typeof client_id === 'string' ? client_id : '';
  const redirectUri = typeof redirect_uri === 'string' ? redirect_uri : '';
  const client = await getClient(clientId);

  if (
    response_type !== 'code' ||
    !client ||
    !client.redirectUris.includes(redirectUri) ||
    typeof state !== 'string' ||
    typeof code_challenge !== 'string' ||
    code_challenge_method !== 'S256'
  ) {
    await recordAudit({ event: 'oidc-authorization', app: clientId || 'unknown', result: 'failure', redirectUri });
    return res.status(400).send('Invalid authorization request');
  }
  if (!req.isAuthenticated?.() || !req.user?.id) {
    return res.redirect('/login?url=' + encodeURIComponent(req.originalUrl));
  }

  const code = createAuthorizationCode(client, redirectUri, req.user.id, code_challenge);
  await recordAudit({ userId: req.user.id, event: 'oidc-authorization', app: clientId, result: 'success', redirectUri });
  const callback = new URL(redirectUri);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', state);
  res.redirect(String(callback));
});
app.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri, code_verifier } = req.body || {};
  if (
    grant_type !== 'authorization_code' ||
    [code, client_id, client_secret, redirect_uri, code_verifier].some((value) => typeof value !== 'string')
  ) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  if (!isTokenServiceConfigured()) return res.status(503).json({ error: 'temporarily_unavailable' });

  const authorizationCode = await exchangeAuthorizationCode({
    code,
    clientId: client_id,
    clientSecret: client_secret,
    redirectUri: redirect_uri,
    codeVerifier: code_verifier,
  });
  if (!authorizationCode) {
    await recordAudit({ event: 'oidc-token-exchange', app: client_id, result: 'failure', redirectUri: redirect_uri });
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const user = await findByUserId(authorizationCode.userId);
  if (!user) {
    await recordAudit({ event: 'oidc-token-exchange', app: client_id, result: 'failure', redirectUri: redirect_uri });
    return res.status(400).json({ error: 'invalid_grant' });
  }

  await recordAudit({ userId: user.userId, event: 'oidc-token-exchange', app: client_id, result: 'success', redirectUri: redirect_uri });

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
app.get('/embed', serveUi('embed.html'));
app.get('/me', protectedPage, serveUi('profile.html'));
app.get('/auth/google', passport.authenticate('google', googleScopes));
app.get(googleCallback, passport.authenticate('google', googleScopes));

const serveEsModule = (source) => (req, res) => {
  console.log(req.headers);
  const host = req.headers['x-forwarded-host'] || req.headers['x-forwarded-for'] || 'localhost';
  const es = source.replace('__API_URL__', 'https://' + host);
  res.set('Content-Type', 'text/javascript').set('Access-Control-Allow-Origin', '*').send(es);
};

app.get('/index.mjs', serveEsModule(esLibrary));
app.get('/dashboard.mjs', serveEsModule(dashboardLibrary));
app.get('/node.mjs', serveEsModule(nodeLibrary));
app.get('/lib.mjs', serveEsModule(esHelper));
app.get('/ui/google.svg', (_req, res) => res.type('image/svg+xml').send(readFileSync('./assets/google.svg', 'utf8')));
app.get('/ui/:asset', (req, res) => {
  const asset = uiAssets[req.params.asset];
  if (!asset) return res.sendStatus(404);
  const type = req.params.asset.endsWith('.css') ? 'text/css' : req.params.asset.endsWith('.svg') ? 'image/svg+xml' : 'text/javascript';
  const dashboardUrl = new URL('/dashboard.mjs', process.env.AUTH_DOMAIN || `https://${req.get('host')}`);
  const source = req.params.asset === 'profile.html'
    ? asset.replace('"@li3/":"https://cdn.li3.dev/@li3/"', '"@li3/":"https://cdn.li3.dev/@li3/","@apphor/":"/"')
    : ['security.html', 'properties.html', 'activity.html', 'oidc-apps.html', 'keys.html'].includes(req.params.asset)
      ? asset.replaceAll("from '/dashboard.mjs'", `from '${dashboardUrl}'`)
      : asset;
  res.type(type).send(
    req.params.asset === 'embed.mjs'
      ? source.replace(
          '__EMBED_ALLOWED_ORIGINS__',
          JSON.stringify(
            (process.env.EMBED_ALLOWED_ORIGINS || '')
              .split(',')
              .map((value) => value.trim())
              .filter(Boolean),
          ),
        )
      : source,
  );
});

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
  await initializeSigningKeys();
  log('Auth is running on port ' + PORT);
});
