import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';

process.env.OIDC_ISSUER = 'https://default-auth.example';
process.env.OIDC_CLIENT_ID = 'default-client';
process.env.OIDC_CLIENT_SECRET = 'default-secret';
const { default: defaultAuthClient, AuthClient, createAuthClient } = await import('../assets/node.mjs');

test('exports a class and one environment-configured default client', () => {
  assert.ok(defaultAuthClient instanceof AuthClient);
  assert.equal(typeof AuthClient, 'function');
  assert.equal(defaultAuthClient.issuer, process.env.OIDC_ISSUER);
  assert.equal(defaultAuthClient.clientId, process.env.OIDC_CLIENT_ID);
  assert.equal(defaultAuthClient.clientSecret, process.env.OIDC_CLIENT_SECRET);
  assert.equal(createAuthClient({ clientId: 'compat' }).clientId, 'compat');
});

test('module utilities and default import work without OIDC_CLIENT_ID', () => {
  const env = { ...process.env, OIDC_ISSUER: 'https://default-auth.example' };
  delete env.OIDC_CLIENT_ID;
  delete env.OIDC_CLIENT_SECRET;
  delete env.AUTH_API_TOKEN;
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "const { default: client, getCookies } = await import('./assets/node.mjs'); if (client.clientId !== undefined || getCookies({ headers: { cookie: 'a=b' } }).a !== 'b' || (await client.getProfile({ headers: {} })) !== null) process.exit(1);",
    ],
    { env, stdio: 'pipe' },
  );
});

test('session/admin routes forward only the per-call cookie; API mint uses a separate bearer token', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response('{}', { status: 200 });
  };
  try {
    const auth = new AuthClient({ issuer: 'https://auth.example', clientId: 'id', authApiToken: 'api-key' });
    const request = { headers: { cookie: 'connect.sid=s%2Fv' } };
    await auth.listOidcClients(request);
    await auth.updateAdminUser(request, 'user/a', { disabled: true });
    await auth.issueSessionToken(
      { headers: { cookie: 'connect.sid=s%2Fv', origin: 'https://app.example' } },
      'dashboard',
    );
    await auth.mintApiToken({ label: 'x', scopes: [] });
    assert.equal(calls[0].options.headers.Cookie, 'connect.sid=s%2Fv');
    assert.equal(calls[0].options.headers.Authorization, undefined);
    assert.equal(calls[0].options.redirect, 'manual');
    assert.equal(calls[1].url, 'https://auth.example/api/v1/admin/users/user%2Fa');
    assert.equal(calls[2].options.headers.Origin, 'https://app.example');
    assert.equal(calls[3].options.headers.Authorization, 'Bearer api-key');
    await assert.rejects(auth.listOidcClients({ headers: {} }), /Authentication required/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('request rejects cross-origin URLs before forwarding session or Auth API credentials', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response('{}');
  };
  try {
    const auth = new AuthClient({ issuer: 'https://auth.example', clientId: 'id', authApiToken: 'api-key' });
    const request = { headers: { cookie: 'connect.sid=secret' } };
    await assert.rejects(
      auth.request('//attacker.invalid/capture', { request, auth: 'session' }),
      /configured issuer origin/,
    );
    await assert.rejects(auth.request('https://attacker.invalid/capture', { auth: 'api' }), /configured issuer origin/);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('session API path values are encoded and audit query values use URL encoding', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return new Response('{}');
  };
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'id' });
    const request = { headers: { cookie: 'connect.sid=s' } };
    await auth.deleteUserApiToken(request, 'client/a', 'token ?');
    await auth.getAudit(request, { app: 'a&b' });
    assert.equal(calls[0], 'https://auth.example/api/v1/api-tokens/client%2Fa/token%20%3F');
    assert.equal(calls[1], 'https://auth.example/api/v1/audit?app=a%26b');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('profile and property helpers return null for unauthenticated or missing data', async () => {
  const originalFetch = globalThis.fetch;
  let profileStatus = 401;
  globalThis.fetch = async (url) =>
    new Response('not found', { status: String(url).includes('/properties/') ? 404 : profileStatus });
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'id' });
    const request = { headers: { cookie: 'connect.sid=session' } };
    assert.equal(await auth.getProfile(request), null);
    assert.equal(await auth.isSessionAuthenticated(request), false);
    assert.equal(await auth.getProperty(request, 'missing'), null);
    profileStatus = 503;
    await assert.rejects(auth.getProfile(request), /503/);
    profileStatus = 401;

    const response = {
      writeHead(status) {
        this.status = status;
      },
      end(body) {
        this.body = body;
      },
    };
    assert.equal(await auth.requireSession(request, response), null);
    assert.equal(response.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('mintApiToken sends the client-bound Auth API token and downstream scopes', async () => {
  const originalFetch = globalThis.fetch;
  let call;
  globalThis.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(JSON.stringify({ token: 'auth_downstream', expiresAt: '2030-01-01T00:00:00.000Z' }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const auth = createAuthClient({
      issuer: 'https://auth.example',
      clientId: 'storage',
      authApiToken: 'auth_management',
    });
    const result = await auth.mintApiToken({ label: 'storage limits', scopes: ['limits:write'] });

    assert.equal(call.url, 'https://auth.example/api/v1/api-tokens/storage/issue');
    assert.equal(call.options.method, 'POST');
    assert.equal(call.options.headers.Authorization, 'Bearer auth_management');
    assert.deepEqual(JSON.parse(call.options.body), { label: 'storage limits', scopes: ['limits:write'] });
    assert.equal(result.token, 'auth_downstream');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('addApiTokenScopes appends scopes using the client-bound Auth API bearer token', async () => {
  const originalFetch = globalThis.fetch;
  let call;
  globalThis.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(JSON.stringify({ scopes: ['storage:limits', 'storage:catalog:read'] }), { status: 200 });
  };
  try {
    const auth = createAuthClient({
      issuer: 'https://auth.example',
      clientId: 'storage',
      authApiToken: 'auth_management',
    });
    const result = await auth.addApiTokenScopes(['storage:catalog:read']);
    assert.equal(call.url, 'https://auth.example/api/v1/api-tokens/storage/scopes');
    assert.equal(call.options.method, 'POST');
    assert.equal(call.options.headers.Authorization, 'Bearer auth_management');
    assert.deepEqual(JSON.parse(call.options.body), { scopes: ['storage:catalog:read'] });
    assert.deepEqual(result.scopes, ['storage:limits', 'storage:catalog:read']);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('revokeApiToken uses the registered client credentials and versioned endpoint', async () => {
  const originalFetch = globalThis.fetch;
  let call;
  globalThis.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(null, { status: 200 });
  };

  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage', clientSecret: 'secret' });
    await auth.revokeApiToken('auth_downstream');
    assert.equal(call.url, 'https://auth.example/api/v1/revoke');
    assert.equal(call.options.method, 'POST');
    assert.equal(call.options.headers.Authorization, `Basic ${Buffer.from('storage:secret').toString('base64')}`);
    assert.equal(new URLSearchParams(call.options.body).get('token'), 'auth_downstream');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('mintApiToken requires a fixed-purpose Auth API token', async () => {
  const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
  await assert.rejects(
    auth.mintApiToken({ label: 'storage limits', scopes: ['limits:write'] }),
    /An Auth API token is required/,
  );
});

test('Auth API client excludes standard OIDC protocol methods', () => {
  const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
  for (const method of [
    'getDiscovery',
    'getJwks',
    'verifyToken',
    'getUserInfo',
    'introspectToken',
    'authorizationUrl',
    'createAuthorizationRequest',
    'exchangeCode',
    'completeAuthorization',
    'refreshToken',
    'revokeRefreshToken',
    'getLogoutUrl',
  ]) {
    assert.equal(auth[method], undefined, `${method} is delegated to openid-client`);
  }
  assert.equal(typeof auth.revokeApiToken, 'function');
  assert.equal(typeof auth.getProfile, 'function');
});

test('property helpers forward the central cookie and URL-encode keys', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(JSON.stringify({ key: 'a/b', value: 'v' }), { status: 200 });
  };
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
    const request = { headers: { cookie: 'connect.sid=session' } };
    await auth.getProperty(request, 'a/b');
    await auth.setProperty(request, 'a/b', 'v');
    await auth.deleteProperty(request, 'a/b');
    assert.deepEqual(
      calls.map(({ url }) => url),
      [
        'https://auth.example/api/v1/properties/a%2Fb',
        'https://auth.example/api/v1/properties',
        'https://auth.example/api/v1/properties/a%2Fb',
      ],
    );
    assert.ok(calls.every(({ options }) => options.headers.Cookie === 'connect.sid=session'));
    assert.equal(calls[1].options.method, 'PUT');
    assert.deepEqual(JSON.parse(calls[1].options.body), { key: 'a/b', value: 'v' });
    assert.equal(calls[2].options.method, 'DELETE');
    assert.equal(auth.removeProperty, auth.deleteProperty);
    assert.equal(await auth.getProperty({ headers: {} }, 'key'), null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
