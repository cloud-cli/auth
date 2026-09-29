import express from 'express';
import { createHash, timingSafeEqual } from 'crypto';
import { readFileSync } from 'fs';
import migrate from '../db/migrations/003_add_user_roles.js';
import { findByEmail, findByUserId, userAsJSON } from './user.js';
import { initDatabase } from './database.js';
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
import {
  addManagedClientScopes,
  createAuthorizationCode,
  createManagedClient,
  exchangeAuthorizationCode,
  getClient,
  isOidcClient,
  listManagedClients,
  removeManagedClient,
  tokenResponse,
  updateManagedClientRedirectUris,
  updateManagedClientScopes,
  verifyClientSecret,
} from './oidc.js';
import {
  authenticate,
  authenticationOptions,
  listAuthenticators,
  registrationOptions,
  registerAuthenticator,
  revokeAuthenticator,
} from './webauthn.js';
import { consumeRecoveryCode, replaceRecoveryCodes } from './recovery.js';
import { getAuditEvents, getAuditOptions, recordAudit } from './audit.js';
import { createApiToken, introspectApiToken, listApiTokens, revokeApiToken } from './api-tokens.js';
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
    'tokens.html',
    'passkey.html',
    'recovery.html',
    'profile.html',
    'account.html',
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

async function adminRoute(req, res, next) {
  if (!req.isAuthenticated?.()) return res.status(403).send('');
  if ((await findByUserId(req.user?.id))?.role !== 'admin') return res.status(403).send('');
  next();
}

function isAllowedBrowserOrigin(origin: string, configuredOrigins: string[]) {
  try {
    const hostname = new URL(origin).hostname;
    return configuredOrigins.some((value) => {
      if (value === origin) return true;
      const domain = value
        .replace(/^https?:\/\//, '')
        .replace(/^\./, '')
        .split('/')[0];
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  } catch {
    return false;
  }
}

function serveUi(name: string) {
  return (_req, res) => {
    let source = name === 'profile.html' ? uiAssets[name].replace('ACCOUNT SECURITY', '') : uiAssets[name];
    if (name === 'login.html') {
      source = source.replace('__TEST_LOGIN_ENABLED__', testLoginEnabled ? 'true' : 'false');
    }
    res.type('html').send(source);
  };
}

const testLoginEnabled = Boolean(process.env.AUTH_TEST_KEYS || process.env.AUTH_TEST_SECRET);

function configuredTestKeys() {
  return (process.env.AUTH_TEST_KEYS || process.env.AUTH_TEST_SECRET || '')
    .split(',')
    .map((key) => key.trim())
    .filter(Boolean);
}

function testKeyHash(key: string) {
  return createHash('sha256').update(key).digest();
}

function isConfiguredTestKey(key: string) {
  if (!key) return false;
  const candidate = testKeyHash(key);
  return configuredTestKeys().some((configured) => timingSafeEqual(candidate, testKeyHash(configured)));
}

function testUserId(key: string) {
  return `test-${testKeyHash(key).toString('hex')}`;
}

function serveAppEntry(req, res) {
  const authenticated = Boolean(req.isAuthenticated?.() && req.user?.id);
  return serveUi(authenticated ? 'profile.html' : 'landing.html')(req, res);
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

app.get('/', serveAppEntry);
app.get('/profile', browserCors, protectedRouteWithRedirect, async (req, res) => {
  const user = await findByUserId(req.user?.id);
  if (user) {
    res.send(userAsJSON(user));
    return;
  }

  res.status(404).send('{}');
});
app.post('/__test__/login', express.json(), async (req, res) => {
  if (!testLoginEnabled) return res.sendStatus(404);

  const authorization = req.get('authorization') || '';
  const bearerKey = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length).trim() : '';
  const key = bearerKey || req.get('x-test-secret') || String(req.body?.key || '');
  if (!isConfiguredTestKey(key)) return res.status(401).json({ error: 'Invalid test key' });

  const userId = testUserId(key);
  const role = 'admin';
  let user = await findByUserId(userId);
  if (!user) {
    user = {
      userId,
      profileId: `test-profile-${testKeyHash(key).toString('hex')}`,
      accessToken: '',
      refreshToken: '',
      name: 'John Doe',
      email: `john.doe+${testKeyHash(key).toString('hex').slice(0, 12)}@example.test`,
      photo: '',
      lastSeen: new Date().toISOString(),
      role,
    };
    const { saveUser } = await import('./database.js');
    await saveUser(user);
  } else if (user.role !== role) {
    user.role = role;
    user.lastSeen = new Date().toISOString();
    const { saveUser } = await import('./database.js');
    await saveUser(user);
  }

  await recordAudit({ userId, event: 'test-authentication', app: 'Test login', result: 'success' });
  req.login(userAsJSON(user), (error) => {
    if (error) return res.status(500).send('Could not create test session');
    req.session.save((saveError) =>
      saveError ? res.status(500).send('Could not persist test session') : res.status(204).send(''),
    );
  });
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
app.get('/keys', adminRoute, async (_req, res) => res.json(await listSigningKeys()));
app.post('/keys/rotate', express.json(), adminRoute, async (_req, res) => {
  try {
    res.status(201).json(await rotateSigningKey());
  } catch (error) {
    res.status(503).json({ error: String(error) });
  }
});
app.get('/audit', protectedRoute, async (req, res) =>
  res.json(
    await getAuditEvents(req.user!.id, {
      app: typeof req.query.app === 'string' ? req.query.app : '',
      event: typeof req.query.event === 'string' ? req.query.event : '',
      limit: Number(req.query.limit) || 20,
      offset: Number(req.query.offset) || 0,
    }),
  ),
);
app.get('/audit/options', protectedRoute, async (req, res) => res.json(await getAuditOptions(req.user!.id)));
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
app.get('/pwa/sw.js', (_req, res) => res.type('javascript').set('Service-Worker-Allowed', '/').send(pwaServiceWorker));
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
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ error: 'Could not persist session' });
        res.status(204).send('');
      });
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
    const result = await createManagedClient(
      String(req.body?.id || ''),
      Array.isArray(req.body?.redirectUris) ? req.body.redirectUris.filter((value) => typeof value === 'string') : [],
      Array.isArray(req.body?.scopes) ? req.body.scopes.filter((value) => typeof value === 'string') : [],
    );
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.get('/api-tokens/me', protectedRoute, async (req, res) => {
  const userId = req.user?.id;
  if (!userId) return res.status(401).send('');
  const clientId = typeof req.query?.clientId === 'string' ? req.query.clientId : undefined;
  res.json(await listApiTokens(userId, clientId));
});
app.get('/api-tokens/:clientId', adminRoute, async (req, res) =>
  res.json(await listApiTokens(req.user!.id, req.params.clientId)),
);
app.post('/api-tokens/:clientId', express.json(), adminRoute, async (req, res) => {
  try {
    res
      .status(201)
      .json(
        await createApiToken(
          req.user!.id,
          req.params.clientId,
          String(req.body?.label || ''),
          Array.isArray(req.body?.scopes) ? req.body.scopes : [],
        ),
      );
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.delete('/api-tokens/:clientId/:tokenId', adminRoute, async (req, res) =>
  res.sendStatus((await revokeApiToken(req.user!.id, req.params.clientId, req.params.tokenId)) ? 204 : 404),
);
app.post('/oauth/introspect', express.urlencoded({ extended: false }), async (req, res) => {
  const authorization = req.get('authorization') || '';
  const [clientId, clientSecret] = authorization.startsWith('Basic ')
    ? Buffer.from(authorization.slice(6), 'base64').toString().split(':')
    : ['', ''];
  const result = await introspectApiToken(String(req.body?.token || ''), clientId, clientSecret);
  res
    .set('Cache-Control', 'private, max-age=30')
    .set('X-Token-Expires-At', String(result?.exp || 0))
    .json(result || { active: false });
});
app.delete('/oidc/clients/:id', adminRoute, async (req, res) =>
  res.sendStatus((await removeManagedClient(req.params.id)) ? 204 : 404),
);
app.post('/oidc/clients/:id/scopes', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      scopes: await addManagedClientScopes(req.params.id, Array.isArray(req.body?.scopes) ? req.body.scopes : []),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.put('/oidc/clients/:id/scopes', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      scopes: await updateManagedClientScopes(req.params.id, Array.isArray(req.body?.scopes) ? req.body.scopes : []),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.put('/oidc/clients/:id/callbacks', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      redirectUris: await updateManagedClientRedirectUris(
        req.params.id,
        Array.isArray(req.body?.redirectUris) ? req.body.redirectUris : [],
      ),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
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

  const validationErrors = [
    response_type !== 'code' && 'unsupported_response_type',
    !client && 'unknown_client',
    client && !client.redirectUris.includes(redirectUri) && 'redirect_uri_not_allowed',
    typeof state !== 'string' && 'missing_state',
    typeof code_challenge !== 'string' && 'missing_code_challenge',
    code_challenge_method !== 'S256' && 'invalid_code_challenge_method',
  ].filter(Boolean);
  if (validationErrors.length) {
    console.warn('OIDC authorization rejected', {
      clientId: clientId || undefined,
      redirectUri: redirectUri || undefined,
      validationErrors,
    });
    await recordAudit({ event: 'oidc-authorization', app: clientId || 'unknown', result: 'failure', redirectUri });
    return res.status(400).send('Invalid authorization request');
  }
  if (!req.isAuthenticated?.() || !req.user?.id) {
    return res.redirect('/login?url=' + encodeURIComponent(req.originalUrl));
  }

  const code = createAuthorizationCode(client!, redirectUri, req.user.id, code_challenge as string);
  await recordAudit({
    userId: req.user.id,
    event: 'oidc-authorization',
    app: clientId,
    result: 'success',
    redirectUri,
  });
  const callback = new URL(redirectUri);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', state as string);
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

  await recordAudit({
    userId: user.userId,
    event: 'oidc-token-exchange',
    app: client_id,
    result: 'success',
    redirectUri: redirect_uri,
  });

  res.json(await tokenResponse(user, client_id));
});
app.post('/revoke', express.urlencoded({ extended: false }), async (req, res) => {
  const authHeader = req.get('authorization') || '';
  const [clientId, clientSecret] = authHeader.startsWith('Basic ')
    ? Buffer.from(authHeader.slice(6), 'base64').toString().split(':')
    : ['', ''];
  const client = await getClient(clientId);
  if (!client || !(await verifyClientSecret(client, clientSecret))) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  res.sendStatus(200);
});
app.get('/.well-known/jwks.json', async (_req, res) => {
  const jwks = await getJwks();
  if (!jwks) return res.status(503).send('JWT service is not configured');

  res.set('Cache-Control', 'public, max-age=3600').json(jwks);
});
app.get('/.well-known/openid-configuration', async (_req, res) => {
  const iss = process.env.AUTH_DOMAIN?.replace(/\/$/, '') || 'http://localhost:3000';
  res.json({
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    userinfo_endpoint: `${iss}/userinfo`,
    jwks_uri: `${iss}/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  });
});
app.get('/userinfo', tokenUser, async (req, res) => {
  const user = await findByUserId(req.tokenUserId);
  if (!user) return res.status(404).send('{}');

  res.json(userAsJSON(user));
});
app.get('/embed', serveUi('embed.html'));
app.get('/me', serveAppEntry);
app.get('/account', protectedPage, serveUi('account.html'));
app.get('/auth/google', passport.authenticate('google', googleScopes));
app.get(googleCallback, passport.authenticate('google', googleScopes));

const serveEsModule = (source) => (req, res) => {
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost || req.get('host') || 'localhost';
  const forwardedProtocol = req.headers['x-forwarded-proto'];
  const protocol = Array.isArray(forwardedProtocol) ? forwardedProtocol[0] : forwardedProtocol || req.protocol;
  const es = source.replace('__API_URL__', `${protocol}://${host}`);
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
  const type = req.params.asset.endsWith('.css')
    ? 'text/css'
    : req.params.asset.endsWith('.svg')
      ? 'image/svg+xml'
      : req.params.asset.endsWith('.html')
        ? 'text/html'
        : 'text/javascript';
  const source = asset.replaceAll("from '/dashboard.mjs'", `from '${req.protocol}://${req.get('host')}/dashboard.mjs'`);
  res
    .set('Cache-Control', 'no-store')
    .type(type)
    .send(
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
async function start() {
  await migrate();
  await initDatabase();
  if (!__TEST__) await initializeSigningKeys();
  app.listen(PORT, () => log('Auth is running on port ' + PORT));
}

start().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
