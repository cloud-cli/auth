import express from 'express';
import { createHash, timingSafeEqual } from 'crypto';
import { readFileSync } from 'fs';
import migrate from '../db/migrations/007_user_management.js';
import {
  findByEmail,
  findByUserId,
  isUserSuspended,
  setPreferredUsername,
  userAsJSON,
  normalizePreferredUsername,
} from './user.js';
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
  verifyIdentityToken,
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
  oidcUserInfo,
  removeManagedClient,
  regenerateManagedClientSecret,
  tokenResponse,
  updateManagedClientRedirectUris,
  updateManagedClientPostLogoutRedirectUris,
  updateManagedClientScopes,
  validateAuthorizationScopes,
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
import {
  createApiToken,
  createAuthApiToken,
  introspectApiToken,
  listApiTokens,
  listAuthApiTokens,
  revokeApiToken,
  revokePresentedApiToken,
  verifyAuthApiToken,
} from './api-tokens.js';
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
const oidcBrowserLibrary = readFileSync('./assets/oidc.mjs', 'utf8');
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
    'users.html',
    'copy-value.html',
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

function protectedRouteWithRedirect(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    const returnUrl = req.get('referrer') || req.get('referer');
    res.set('Location', '/login?url=' + returnUrl);
    return res.status(401).send('');
  }

  next();
}

function logout(req, res) {
  req.logout((logoutError) => {
    if (logoutError) return res.status(500).send('');
    req.session.destroy((sessionError) => {
      if (sessionError) return res.status(500).send('');
      res.clearCookie('connect.sid', { domain: process.env.SESSION_DOMAIN || undefined, path: '/' });
      res.status(202).send('OK');
    });
  });
}

function bearerToken(req) {
  const authorization = req.get('authorization') || '';
  return authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : '';
}

async function tokenUser(req, res, next) {
  const token = bearerToken(req);
  let audience = req.get('x-auth-audience') || '';

  if (!audience && token) {
    try {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      audience = typeof payload.aud === 'string' ? payload.aud : '';
    } catch {
      return res.status(401).send('');
    }
  }

  if (!token || !audience || (!isAllowedAudience(audience) && !(await isOidcClient(audience)))) {
    return res.status(401).send('');
  }

  try {
    const { payload } = await verifyAccessToken(token, audience);
    if (!payload.sub) return res.status(401).send('');
    const identity = await findByUserId(String(payload.sub));
    if (!identity || (await isUserSuspended(identity.userId))) return res.status(401).send('');

    req.tokenUserId = payload.sub;
    req.tokenAudience = audience;
    req.tokenScopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/).filter(Boolean) : [];
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
  if (!req.isAuthenticated?.() || (await findByUserId(req.user?.id))?.role !== 'admin') {
    if (!req.path.startsWith('/api/') && req.accepts('html')) {
      const message = req.isAuthenticated?.()
        ? 'Administrator access is required to view this page.'
        : 'Sign in with an administrator account to continue.';
      return res.status(403).type('html').send(renderAuthError(message));
    }
    return res.status(403).send('');
  }
  next();
}

function registerUserAdminRoutes() {
  app.get('/api/v1/admin/users', adminRoute, async (_req, res) => {
    const { all } = await import('./database.js');
    res.json(
      await all(
        `SELECT auth_user.user_id AS id, auth_user.profile_id AS profileId, auth_user.email, auth_user.name,
                auth_user.photo, COALESCE(auth_activity.last_authenticated, auth_user.last_seen) AS lastSeen,
                auth_user.role, auth_user.preferred_username AS preferredUsername, auth_user.disabled,
                EXISTS (SELECT 1 FROM auth_blocked_identity b WHERE b.profile_id = auth_user.profile_id) AS blocked
         FROM auth_user
         LEFT JOIN (
           SELECT user_id, MAX(timestamp) AS last_authenticated
           FROM auth_audit_event
           WHERE result = 'success' AND event IN (
             'google-authentication', 'test-authentication', 'recovery-authentication',
             'passkey-authentication', 'qr-approval', 'oidc-authorization', 'oidc-token-exchange'
           )
           GROUP BY user_id
         ) auth_activity ON auth_activity.user_id = auth_user.user_id
         ORDER BY auth_user.email COLLATE NOCASE`,
      ),
    );
  });
  app.patch('/api/v1/admin/users/:id', express.json(), adminRoute, async (req, res) => {
    const { all, run } = await import('./database.js');
    const id = req.params.id;
    const target: any = (await all<any>('SELECT * FROM auth_user WHERE user_id = ?', [id]))[0];
    if (!target) return res.sendStatus(404);
    const body = req.body || {};
    if (id === req.user!.id && (body.disabled === true || (body.role && body.role !== 'admin')))
      return res.status(409).json({ error: 'Cannot disable or demote your own account.' });
    const admins = await all<any>("SELECT user_id FROM auth_user WHERE role = 'admin'");
    if (target.role === 'admin' && admins.length <= 1 && body.disabled === true)
      return res.status(409).json({ error: 'Cannot disable the final administrator.' });
    if ('preferred_username' in body) {
      try {
        const username = normalizePreferredUsername(body.preferred_username);
        await run('UPDATE auth_user SET preferred_username = ? WHERE user_id = ?', [username, id]);
        return res.json({ preferred_username: username });
      } catch (error) {
        return res.status(400).json({ error: String(error) });
      }
    }
    if (body.disabled === true || body.disabled === false) {
      await run('UPDATE auth_user SET disabled = ? WHERE user_id = ?', [body.disabled ? 1 : 0, id]);
      if (body.disabled) {
        const sessions = await all('SELECT sid, session FROM auth_session');
        for (const item of sessions as any[]) {
          try {
            if (JSON.parse(item.session)?.passport?.user === id)
              await run('DELETE FROM auth_session WHERE sid = ?', [item.sid]);
          } catch {}
        }
      }
      return res.json({ ok: true });
    }
    if (body.blocked === true || body.blocked === false) {
      if (body.blocked && id === req.user!.id)
        return res.status(409).json({ error: 'Cannot block your own sign-in identity.' });
      if (
        body.blocked &&
        target.role === 'admin' &&
        (await all<any>("SELECT user_id FROM auth_user WHERE role = 'admin'")).length <= 1
      )
        return res.status(409).json({ error: 'Cannot block the final administrator.' });
      if (body.blocked)
        await run('INSERT OR REPLACE INTO auth_blocked_identity (profile_id, blocked_at) VALUES (?, ?)', [
          target.profile_id,
          new Date().toISOString(),
        ]);
      else await run('DELETE FROM auth_blocked_identity WHERE profile_id = ?', [target.profile_id]);
      if (body.blocked) {
        const sessions = await all('SELECT sid, session FROM auth_session');
        for (const item of sessions as any[]) {
          try {
            if (JSON.parse(item.session)?.passport?.user === id)
              await run('DELETE FROM auth_session WHERE sid = ?', [item.sid]);
          } catch {}
        }
      }
      return res.json({ ok: true });
    }
    return res.status(400).json({ error: 'Unsupported user update.' });
  });
  app.delete('/api/v1/admin/users/:id', adminRoute, async (req, res) => {
    const { all, run } = await import('./database.js');
    const id = req.params.id;
    const users = await all<any>('SELECT user_id, profile_id, role FROM auth_user ORDER BY user_id');
    const target = users.find((user: any) => user.user_id === id);
    if (!target) return res.sendStatus(404);
    if (target.role === 'admin' && users.filter((user: any) => user.role === 'admin').length <= 1)
      return res.status(409).json({ error: 'Cannot delete the final administrator.' });
    const sessions = await all('SELECT sid, session FROM auth_session');
    for (const session of sessions as any[]) {
      try {
        if (JSON.parse(session.session)?.passport?.user === id)
          await run('DELETE FROM auth_session WHERE sid = ?', [session.sid]);
      } catch {}
    }
    for (const table of ['auth_authenticator', 'auth_api_token', 'auth_property', 'auth_qr_login'])
      await run(`DELETE FROM ${table} WHERE user_id = ?`, [id]);
    await run('DELETE FROM auth_audit_event WHERE user_id = ?', [id]);
    await run('DELETE FROM auth_blocked_identity WHERE profile_id = ?', [target.profile_id]);
    await run('DELETE FROM auth_user WHERE user_id = ?', [id]);
    res.json({ ok: true });
  });
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
    res.status(200).set('Cache-Control', 'no-store').vary('Cookie').type('html').end(source);
  };
}

const testLoginEnabled = Boolean(process.env.AUTH_TEST_KEYS || process.env.AUTH_TEST_SECRET);

function renderAuthError(message: string) {
  const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const escaped = message.replace(/[&<>"']/g, (character) => entities[character]);
  return uiAssets['login.html']
    .replace(
      '<h2 class="text-3xl font-extrabold tracking-[-.03em]">Welcome back</h2>',
      `<h2 class="text-3xl font-extrabold tracking-[-.03em]">Welcome back</h2><p role="alert" class="rounded-xl bg-rose-50 p-3 text-sm text-rose-700">${escaped}</p><div class="flex flex-wrap gap-3"><a class="rounded-xl bg-violet px-4 py-3 text-sm font-bold text-white" href="/login">Try signing in again</a><a class="rounded-xl border border-slate-200 px-4 py-3 text-sm font-bold" href="/">Return to Auth home</a></div>`,
    )
    .replace('__TEST_LOGIN_ENABLED__', testLoginEnabled ? 'true' : 'false');
}

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
  const sessionCookieCount = String(req.get('cookie') || '')
    .split(';')
    .filter((cookie) => cookie.trim().startsWith('connect.sid=')).length;
  console.info('App entry session check', {
    path: req.path,
    authenticated,
    hasUserId: Boolean(req.user?.id),
    hasSession: Boolean(req.session),
    hasPassportUser: Boolean(req.session?.passport?.user),
    sessionCookieCount,
  });
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
registerUserAdminRoutes();

app.use((req, res, next) => {
  res.on('finish', () => {
    const date = new Date().toISOString().slice(0, 19);
    console.log(`[${date}] ${req.method} ${req.url} ${res.statusCode}`);
  });
  next();
});

app.get('/', serveAppEntry);
app.get('/api/v1/profile', browserCors, protectedRouteWithRedirect, async (req, res) => {
  const user = await findByUserId(req.user?.id);
  if (user) {
    res.send(userAsJSON(user));
    return;
  }

  res.status(404).send('{}');
});
app.put('/api/v1/profile/preferred-username', express.json(), protectedRoute, async (req, res) => {
  try {
    const preferredUsername = await setPreferredUsername(req.user!.id, req.body?.preferred_username);
    res.status(201).json({ preferred_username: preferredUsername });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Could not set preferred username.';
    const status = /already been set|already taken/i.test(message) ? 409 : 400;
    res.status(status).json({ error: message });
  }
});
app.post('/__test__/login', express.json(), async (req, res) => {
  if (!testLoginEnabled) return res.sendStatus(404);

  const authorization = req.get('authorization') || '';
  const bearerKey = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length).trim() : '';
  const key = bearerKey || req.get('x-test-secret') || String(req.body?.key || '');
  if (!isConfiguredTestKey(key)) {
    console.warn('Test login rejected: invalid key');
    return res.status(401).json({ error: 'Invalid test key' });
  }

  const userId = testUserId(key);
  const role = 'admin';
  console.info('Test login accepted; creating session');
  let user = await findByUserId(userId);
  if (user && (await isUserSuspended(user.userId))) return res.status(403).json({ error: 'This account is disabled.' });
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
    if (error) {
      console.error('Test login session creation failed', { errorName: error.name });
      return res.status(500).send('Could not create test session');
    }
    req.session.save((saveError) => {
      if (saveError) {
        console.error('Test login session persistence failed', { errorName: saveError.name });
        return res.status(500).send('Could not persist test session');
      }
      console.info('Test login session persisted', {
        authenticated: Boolean(req.isAuthenticated?.()),
        hasUserId: Boolean(req.user?.id),
        hasSession: Boolean(req.session),
      });
      return res.status(204).send('');
    });
  });
});
app.head('/api/v1/profile', browserCors, protectedRoute, (_req, res) => {
  res.status(204).send('');
});
app.delete('/api/v1/profile', protectedRoute, logout);
app.get('/login', (req, res) => {
  const returnUrl = typeof req.query.url === 'string' ? req.query.url : '/me';
  if (req.isAuthenticated?.() && req.user?.id && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    const destination = new URL(returnUrl, `${req.protocol}://${req.get('host')}`);
    const signinNonce = typeof req.query.signinNonce === 'string' ? req.query.signinNonce : '';
    if (/^[a-zA-Z0-9_-]{1,128}$/.test(signinNonce)) destination.searchParams.set('signinNonce', signinNonce);
    return res.redirect(302, destination.pathname + destination.search + destination.hash);
  }
  serveUi('login.html')(req, res);
});
app.get('/webauthn/login', serveUi('passkey.html'));
app.get('/recovery', serveUi('recovery.html'));
app.get('/oidc', adminRoute, (_req, res) => res.redirect('/me#oidc'));
app.get('/auth-api-tokens', adminRoute, (_req, res) => res.redirect('/me#auth-api-tokens'));
app.get('/api/v1/keys', adminRoute, async (_req, res) => res.json(await listSigningKeys()));
app.post('/api/v1/keys/rotate', express.json(), adminRoute, async (_req, res) => {
  try {
    res.status(201).json(await rotateSigningKey());
  } catch (error) {
    res.status(503).json({ error: String(error) });
  }
});
app.get('/api/v1/audit', protectedRoute, async (req, res) =>
  res.json(
    await getAuditEvents(req.user!.id, {
      app: typeof req.query.app === 'string' ? req.query.app : '',
      event: typeof req.query.event === 'string' ? req.query.event : '',
      limit: Number(req.query.limit) || 20,
      offset: Number(req.query.offset) || 0,
    }),
  ),
);
app.get('/api/v1/audit/options', protectedRoute, async (req, res) => res.json(await getAuditOptions(req.user!.id)));
app.post('/api/v1/recovery', express.urlencoded({ extended: false }), async (req, res) => {
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
app.get('/api/v1/qr-login/start', async (req, res) => {
  const page = await qrLoginPage(req.sessionID, typeof req.query.url === 'string' ? req.query.url : '/me');
  res.json(page);
});
app.get('/qr-login', serveUi('qr-login.html'));
app.get('/api/v1/qr-login/status', async (req, res) => {
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
app.get('/api/v1/qr-login/details', protectedRoute, async (req, res) => {
  try {
    const token = typeof req.query.transaction === 'string' ? req.query.transaction : '';
    res.json(await qrLoginDetails(token));
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/api/v1/qr-login/approve', express.json(), protectedRoute, async (req, res) => {
  try {
    await approveQrLogin(String(req.body?.transaction || ''), req.user!.id);
    await recordAudit({ userId: req.user!.id, event: 'qr-approval', app: 'QR login', result: 'success' });
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.post('/api/v1/qr-login/deny', express.json(), protectedRoute, async (req, res) => {
  try {
    await denyQrLogin(String(req.body?.transaction || ''));
    res.sendStatus(204);
  } catch {
    res.status(410).json({ error: 'Expired QR login' });
  }
});
app.get('/pwa/', serveUi('pwa.html'));
app.get('/ui/sw.js', (_req, res) => res.type('javascript').set('Service-Worker-Allowed', '/').send(pwaServiceWorker));
app.get('/api/v1/webauthn/register/options', protectedRoute, async (req, res) => {
  res.json(await registrationOptions(req.user!.id));
});
app.post('/api/v1/webauthn/register/verify', express.json(), protectedRoute, async (req, res) => {
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
app.get('/api/v1/webauthn/authentication/options', async (req, res) => {
  const loginHint = typeof req.query.login_hint === 'string' ? req.query.login_hint : '';
  const user = loginHint
    ? loginHint.includes('@')
      ? await findByEmail(loginHint)
      : await findByUserId(loginHint)
    : null;
  res.json(await authenticationOptions(user && !(await isUserSuspended(user.userId)) ? user.userId : undefined));
});
app.post('/api/v1/webauthn/authentication/verify', express.json(), async (req, res) => {
  try {
    const { userId } = await authenticate(req.body);
    const user = await findByUserId(userId);
    if (!user || (await isUserSuspended(user.userId))) return res.status(401).json({ error: 'User not found' });
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
app.get('/api/v1/webauthn/credentials', protectedRoute, async (req, res) => {
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
app.post('/api/v1/recovery-codes', express.json(), protectedRoute, async (req, res) => {
  const user = await findByUserId(req.user!.id);
  if (!user) return res.status(404).send('');
  res.json({ codes: await replaceRecoveryCodes(user) });
});
app.delete('/api/v1/webauthn/credentials/:credentialId', protectedRoute, async (req, res) => {
  const revoked = await revokeAuthenticator(req.user!.id, req.params.credentialId);
  res.sendStatus(revoked ? 204 : 404);
});
app.get('/api', (req, res) => {
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost || req.host;
  res.type('application/json').send(openApiSpec.replace('__HOSTNAME__', host));
});
app.get('/api/v1/oidc/clients', adminRoute, async (_req, res) => res.json(await listManagedClients()));
app.post('/api/v1/oidc/clients', express.json(), adminRoute, async (req, res) => {
  try {
    const result = await createManagedClient(
      String(req.body?.id || ''),
      Array.isArray(req.body?.redirectUris) ? req.body.redirectUris.filter((value) => typeof value === 'string') : [],
      Array.isArray(req.body?.scopes) ? req.body.scopes.filter((value) => typeof value === 'string') : [],
      req.body?.isPublic === true,
      Array.isArray(req.body?.postLogoutRedirectUris)
        ? req.body.postLogoutRedirectUris.filter((value) => typeof value === 'string')
        : [],
    );
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.get('/api/v1/api-tokens/me', protectedRoute, async (req, res) => {
  const userId = req.user?.id;
  if (!userId) return res.status(401).send('');
  const clientId = typeof req.query?.clientId === 'string' ? req.query.clientId : undefined;
  res.json(await listApiTokens(userId, clientId));
});
app.get('/api/v1/api-tokens/:clientId', adminRoute, async (req, res) =>
  res.json(await listApiTokens(req.user!.id, req.params.clientId)),
);
app.get('/api/v1/auth-api-tokens/:clientId', adminRoute, async (req, res) =>
  res.json(await listAuthApiTokens(req.params.clientId)),
);
app.post('/api/v1/auth-api-tokens/:clientId', express.json(), adminRoute, async (req, res) => {
  try {
    const result = await createAuthApiToken(req.params.clientId, String(req.body?.label || ''));
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.delete('/api/v1/auth-api-tokens/:clientId/:tokenId', adminRoute, async (req, res) =>
  res.sendStatus((await revokeApiToken(req.params.clientId, req.params.clientId, req.params.tokenId)) ? 204 : 404),
);
app.post('/api/v1/api-tokens/:clientId', express.json(), adminRoute, async (req, res) => {
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
app.post('/api/v1/api-tokens/:clientId/issue', express.json(), async (req, res) => {
  const client = await getClient(req.params.clientId);
  const authorization = req.get('authorization') || '';
  const authToken = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : '';
  if (!client || !(await verifyAuthApiToken(authToken, req.params.clientId))) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  try {
    const scopes = Array.isArray(req.body?.scopes) ? req.body.scopes : [];
    if (scopes.some((scope) => typeof scope !== 'string')) {
      return res.status(400).json({ error: 'invalid_scope' });
    }
    const result = await createApiToken(client.id, client.id, String(req.body?.label || ''), scopes);
    res.status(201).json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message === 'Unknown OIDC client' || message === 'Invalid token scope') {
      return res.status(400).json({ error: message === 'Invalid token scope' ? 'invalid_scope' : 'invalid_client' });
    }
    throw error;
  }
});
app.delete('/api/v1/api-tokens/:clientId/:tokenId', adminRoute, async (req, res) =>
  res.sendStatus((await revokeApiToken(req.user!.id, req.params.clientId, req.params.tokenId)) ? 204 : 404),
);
app.post('/oauth/introspect', express.urlencoded({ extended: false }), async (req, res) => {
  const authorization = req.get('authorization') || '';
  const [clientId, clientSecret] = authorization.startsWith('Basic ')
    ? Buffer.from(authorization.slice(6), 'base64').toString().split(':')
    : ['', ''];
  const result = await introspectApiToken(String(req.body?.token || ''), clientId, clientSecret);
  res
    .set('Cache-Control', 'no-store')
    .set('X-Token-Expires-At', String(result?.exp || 0))
    .json(result || { active: false });
});
app.delete('/api/v1/oidc/clients/:id', adminRoute, async (req, res) =>
  res.sendStatus((await removeManagedClient(req.params.id)) ? 204 : 404),
);

app.put('/api/v1/oidc/clients/:id/secret', adminRoute, express.json(), async (req, res) => {
  try {
    const result = await regenerateManagedClientSecret(req.params.id);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message === 'Client not found') return res.status(404).json({ error: message });
    res.status(400).json({ error: message });
  }
});
app.post('/api/v1/oidc/clients/:id/scopes', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      scopes: await addManagedClientScopes(req.params.id, Array.isArray(req.body?.scopes) ? req.body.scopes : []),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.put('/api/v1/oidc/clients/:id/scopes', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      scopes: await updateManagedClientScopes(req.params.id, Array.isArray(req.body?.scopes) ? req.body.scopes : []),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.put('/api/v1/oidc/clients/:id/callbacks', express.json(), adminRoute, async (req, res) => {
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
app.put('/api/v1/oidc/clients/:id/logout-redirects', express.json(), adminRoute, async (req, res) => {
  try {
    res.json({
      postLogoutRedirectUris: await updateManagedClientPostLogoutRedirectUris(
        req.params.id,
        Array.isArray(req.body?.postLogoutRedirectUris) ? req.body.postLogoutRedirectUris : [],
      ),
    });
  } catch (error) {
    res.status(400).json({ error: String(error) });
  }
});
app.options('/api/v1/session/token', sessionTokenCors, (_req, res) => res.sendStatus(204));
app.post('/api/v1/session/token', express.json(), sessionTokenCors, protectedRoute, async (req, res) => {
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
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, nonce } =
    req.query;
  const clientId = typeof client_id === 'string' ? client_id : '';
  const redirectUri = typeof redirect_uri === 'string' ? redirect_uri : '';
  const hasScope = typeof scope !== 'undefined';
  const requestedScopes = typeof scope === 'string' && scope.trim().length > 0 ? scope.trim().split(/\s+/) : ['openid'];
  const client = await getClient(clientId);

  const validationErrors = [
    response_type !== 'code' && 'unsupported_response_type',
    !client && 'unknown_client',
    client && !client.redirectUris.includes(redirectUri) && 'redirect_uri_not_allowed',
    typeof state !== 'string' && 'missing_state',
    typeof state === 'string' && state.length === 0 && 'missing_state',
    (typeof code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge)) && 'invalid_code_challenge',
    code_challenge_method !== 'S256' && 'invalid_code_challenge_method',
    hasScope && typeof scope !== 'string' && 'invalid_scope',
    typeof nonce === 'string' && (nonce.length === 0 || nonce.length > 512) && 'invalid_nonce',
    client && !validateAuthorizationScopes(requestedScopes) && 'invalid_scope',
  ].filter(Boolean);
  if (validationErrors.length) {
    console.warn('OIDC authorization rejected', {
      clientId: clientId || undefined,
      redirectUri: redirectUri || undefined,
      validationErrors,
    });
    await recordAudit({ event: 'oidc-authorization', app: clientId || 'unknown', result: 'failure', redirectUri });
    if (client && client.redirectUris.includes(redirectUri)) {
      const callback = new URL(redirectUri);
      callback.searchParams.set('error', 'invalid_request');
      callback.searchParams.set('error_description', 'The sign-in request is invalid or expired. Start a new sign-in.');
      if (typeof state === 'string' && state.length > 0 && state.length <= 1024)
        callback.searchParams.set('state', state);
      return res.redirect(String(callback));
    }
    return res
      .status(400)
      .type('html')
      .send(renderAuthError('This sign-in request is invalid or has expired. Start again from the application.'));
  }
  if (!req.isAuthenticated?.() || !req.user?.id) {
    return res.redirect('/login?url=' + encodeURIComponent(req.originalUrl));
  }

  let code: string;
  try {
    code = createAuthorizationCode(
      client!,
      redirectUri,
      req.user.id,
      code_challenge as string,
      requestedScopes,
      typeof nonce === 'string' ? nonce : undefined,
    );
  } catch {
    return res.status(400).type('html').send(renderAuthError('This application requested unsupported access.'));
  }
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
  const body = req.body || {};
  const clientId = body.client_id;
  const clientSecret = body.client_secret;
  const { grant_type, code, redirect_uri, code_verifier } = body;
  if (
    grant_type !== 'authorization_code' ||
    [code, clientId, redirect_uri, code_verifier].some((value) => typeof value !== 'string') ||
    (typeof clientSecret !== 'string' && (await getClient(String(clientId || '')))?.isPublic !== true)
  ) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  if (!isTokenServiceConfigured()) return res.status(503).json({ error: 'temporarily_unavailable' });

  const authorizationCode = await exchangeAuthorizationCode({
    code,
    clientId,
    clientSecret: typeof clientSecret === 'string' ? clientSecret : '',
    redirectUri: redirect_uri,
    codeVerifier: code_verifier,
  });
  if (!authorizationCode) {
    await recordAudit({ event: 'oidc-token-exchange', app: clientId, result: 'failure', redirectUri: redirect_uri });
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const user = await findByUserId(authorizationCode.userId);
  if (!user || (await isUserSuspended(user.userId))) {
    await recordAudit({ event: 'oidc-token-exchange', app: clientId, result: 'failure', redirectUri: redirect_uri });
    return res.status(400).json({ error: 'invalid_grant' });
  }

  await recordAudit({
    userId: user.userId,
    event: 'oidc-token-exchange',
    app: clientId,
    result: 'success',
    redirectUri: redirect_uri,
  });

  res.json(await tokenResponse(user, clientId, authorizationCode.scopes, authorizationCode.nonce));
});
app.get('/logout', async (req, res) => {
  const idTokenHint = typeof req.query.id_token_hint === 'string' ? req.query.id_token_hint : '';
  const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : '';
  const postLogoutRedirectUri =
    typeof req.query.post_logout_redirect_uri === 'string' ? req.query.post_logout_redirect_uri : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  let redirect: URL | undefined;

  if (postLogoutRedirectUri) {
    if (!idTokenHint || !clientId)
      return res.status(400).type('html').send(renderAuthError('This sign-out request is invalid or has expired.'));
    const client = await getClient(clientId);
    if (!client || !client.postLogoutRedirectUris.includes(postLogoutRedirectUri)) {
      return res
        .status(400)
        .type('html')
        .send(renderAuthError('This application cannot receive the sign-out response.'));
    }
    try {
      const { payload } = await verifyIdentityToken(idTokenHint, clientId);
      if (!payload.sub || (req.user?.id && req.user.id !== payload.sub)) {
        return res.status(400).type('html').send(renderAuthError('This sign-out session is invalid or has expired.'));
      }
    } catch {
      return res.status(400).type('html').send(renderAuthError('This sign-out session is invalid or has expired.'));
    }
    redirect = new URL(postLogoutRedirectUri);
    if (state) redirect.searchParams.set('state', state);
  } else if (idTokenHint && clientId) {
    try {
      await verifyIdentityToken(idTokenHint, clientId);
    } catch {
      return res.status(400).type('html').send(renderAuthError('This sign-out session is invalid or has expired.'));
    }
  }

  req.logout((logoutError) => {
    if (logoutError)
      return res.status(500).type('html').send(renderAuthError('Could not complete sign-out. Please try again.'));
    req.session.destroy((sessionError) => {
      if (sessionError)
        return res.status(500).type('html').send(renderAuthError('Could not complete sign-out. Please try again.'));
      res.clearCookie('connect.sid', { domain: process.env.SESSION_DOMAIN || undefined, path: '/' });
      res.redirect(redirect ? String(redirect) : '/');
    });
  });
});
app.post('/api/v1/revoke', express.urlencoded({ extended: false }), async (req, res) => {
  const authHeader = req.get('authorization') || '';
  const decodedCredentials = authHeader.startsWith('Basic ')
    ? Buffer.from(authHeader.slice(6), 'base64').toString()
    : '';
  const separator = decodedCredentials.indexOf(':');
  const clientId = separator < 0 ? '' : decodedCredentials.slice(0, separator);
  const clientSecret = separator < 0 ? '' : decodedCredentials.slice(separator + 1);
  const client = await getClient(clientId);
  if (!client || !(await verifyClientSecret(client, clientSecret))) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  const token = typeof req.body?.token === 'string' ? req.body.token : '';
  if (token) await revokePresentedApiToken(token, clientId);
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
    end_session_endpoint: `${iss}/logout`,
    userinfo_endpoint: `${iss}/userinfo`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'name', 'preferred_username', 'email', 'picture', 'photo'],
  });
});
app.get('/userinfo', tokenUser, async (req, res) => {
  const user = await findByUserId(req.tokenUserId);
  if (!user) return res.status(404).send('{}');

  res.json(oidcUserInfo(user, req.tokenScopes || []));
});
app.get('/me', serveAppEntry);
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
app.get('/oidc.mjs', serveEsModule(oidcBrowserLibrary));
app.get('/node.mjs', serveEsModule(nodeLibrary));
app.get('/ui/dashboard.mjs', serveEsModule(dashboardLibrary));
app.get('/ui/lib.mjs', serveEsModule(esHelper));
app.get('/ui/google.svg', (_req, res) => res.type('image/svg+xml').send(readFileSync('./assets/google.svg', 'utf8')));
app.get('/ui/:asset', (req, res) => {
  const asset = uiAssets[req.params.asset];
  if (!asset) return res.sendStatus(404);
  const type = req.params.asset.endsWith('.css')
    ? 'text/css'
    : req.params.asset.endsWith('.svg')
      ? 'image/svg+xml'
      : req.params.asset.endsWith('.webmanifest')
        ? 'application/manifest+json'
        : req.params.asset.endsWith('.html')
          ? 'text/html'
          : 'text/javascript';
  const browserOrigins = [process.env.AUTH_ALLOWED_ORIGINS, process.env.EMBED_ALLOWED_ORIGINS]
    .flatMap((value) => (value || '').split(','))
    .map((value) => value.trim())
    .filter(Boolean);
  const source = asset
    .replaceAll("from '/ui/dashboard.mjs'", `from '${req.protocol}://${req.get('host')}/ui/dashboard.mjs'`)
    .replace('__BROWSER_ALLOWED_ORIGINS__', JSON.stringify(browserOrigins));
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

app.put('/api/v1/properties', protectedRoute, async (req, res) => {
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

app.get('/api/v1/properties', protectedRoute, async (req, res) => {
  try {
    const properties = await getProperties(req.user?.id);
    res.status(200).send(properties);
  } catch (e) {
    res.status(500).send('');
    console.error(e);
  }
});

app.delete('/api/v1/properties/:key', protectedRoute, async (req, res) => {
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

app.get('/api/v1/properties/:key', protectedRoute, async (req, res) => {
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
