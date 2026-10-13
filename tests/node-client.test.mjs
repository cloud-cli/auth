import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
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
      "const { default: client, getCookies } = await import('./assets/node.mjs'); let requiresClientId = false; try { client.createAuthorizationRequest({ redirectUri: 'https://app.example/callback' }); } catch (error) { requiresClientId = /OIDC_CLIENT_ID/.test(error.message); } if (client.clientId !== undefined || !requiresClientId || getCookies({ headers: { cookie: 'a=b' } }).a !== 'b' || (await client.getProfile({ headers: {} })) !== null) process.exit(1);",
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

test('OIDC authorization requests include state, nonce, openid scopes, and S256 PKCE', () => {
  const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
  const request = auth.createAuthorizationRequest({ redirectUri: 'https://app.example/callback' });
  const url = new URL(request.url);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'openid profile email');
  assert.equal(url.searchParams.get('state'), request.state);
  assert.equal(url.searchParams.get('nonce'), request.nonce);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('code_challenge').length, 43);
  assert.equal(request.codeVerifier.length, 43);
  assert.equal(request.redirectUri, 'https://app.example/callback');

  const offlineRequest = auth.createAuthorizationRequest({
    redirectUri: 'https://app.example/callback',
    scope: 'openid profile email offline_access',
  });
  assert.equal(new URL(offlineRequest.url).searchParams.get('scope'), 'openid profile email offline_access');
});

test('completeAuthorization validates callback state, PKCE exchange, ID token, and nonce', async () => {
  const originalFetch = globalThis.fetch;
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'callback-key';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage', clientSecret: 'secret' });
  const transaction = auth.createAuthorizationRequest({ redirectUri: 'https://app.example/callback?tenant=west' });
  const callback = new URL(transaction.redirectUri);
  callback.searchParams.set('code', 'one-time-code');
  callback.searchParams.set('state', transaction.state);
  let responseNonce = transaction.nonce;
  let responseNbf;
  const accessToken = 'access-token';
  const atHash = createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url');
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url) === 'https://auth.example/token') {
      const head = encode({ alg: 'RS256', kid: 'callback-key' });
      const payload = encode({
        iss: 'https://auth.example',
        aud: 'storage',
        sub: 'user-1',
        nonce: responseNonce,
        at_hash: atHash,
        iat: Math.floor(Date.now() / 1000),
        exp: 4102444800,
        ...(responseNbf !== undefined ? { nbf: responseNbf } : {}),
      });
      const idToken = `${head}.${payload}.${sign('RSA-SHA256', Buffer.from(`${head}.${payload}`), privateKey).toString('base64url')}`;
      return new Response(JSON.stringify({ id_token: idToken, access_token: accessToken }), { status: 200 });
    }
    return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
  };

  try {
    const invalidState = new URL(callback);
    invalidState.searchParams.set('state', 'wrong-state');
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: invalidState, transaction }),
      /Invalid OIDC callback state/,
    );
    assert.equal(calls.length, 0);

    const invalidLocation = new URL(callback);
    invalidLocation.pathname = '/unexpected-callback';
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: invalidLocation, transaction }),
      /does not match the login redirect URI/,
    );
    const invalidTenant = new URL(callback);
    invalidTenant.searchParams.set('tenant', 'east');
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: invalidTenant, transaction }),
      /does not match the login redirect URI/,
    );
    const duplicateCode = new URL(callback);
    duplicateCode.searchParams.append('code', 'second-code');
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: duplicateCode, transaction }),
      /exactly one authorization code/,
    );
    assert.equal(calls.length, 0);

    const result = await auth.completeAuthorization({ callbackUrl: callback, transaction });
    assert.equal(result.tokens.access_token, 'access-token');
    assert.equal(result.claims.sub, 'user-1');
    assert.equal(new URLSearchParams(calls[0].options.body).get('code'), 'one-time-code');
    assert.equal(new URLSearchParams(calls[0].options.body).get('code_verifier'), transaction.codeVerifier);
    assert.equal(new URLSearchParams(calls[0].options.body).get('redirect_uri'), transaction.redirectUri);

    responseNonce = 'wrong-nonce';
    const secondTransaction = auth.createAuthorizationRequest({ redirectUri: transaction.redirectUri });
    const secondCallback = new URL(secondTransaction.redirectUri);
    secondCallback.searchParams.set('code', 'another-code');
    secondCallback.searchParams.set('state', secondTransaction.state);
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: secondCallback, transaction: secondTransaction }),
      /Invalid OIDC ID token claims/,
    );

    responseNonce = secondTransaction.nonce;
    responseNbf = 'not-a-number';
    const thirdTransaction = auth.createAuthorizationRequest({ redirectUri: transaction.redirectUri });
    const thirdCallback = new URL(thirdTransaction.redirectUri);
    thirdCallback.searchParams.set('code', 'third-code');
    thirdCallback.searchParams.set('state', thirdTransaction.state);
    await assert.rejects(
      auth.completeAuthorization({ callbackUrl: thirdCallback, transaction: thirdTransaction }),
      /Invalid JWT not-before claim/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('refreshToken exchanges a rotating OIDC refresh token server-to-server', async () => {
  const originalFetch = globalThis.fetch;
  let call;
  globalThis.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(JSON.stringify({ access_token: 'new-access', refresh_token: 'new-refresh' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage', clientSecret: 'secret' });
    const result = await auth.refreshToken({ refreshToken: 'old-refresh', scope: 'openid' });
    assert.equal(call.url, 'https://auth.example/token');
    assert.equal(call.options.method, 'POST');
    const body = new URLSearchParams(call.options.body);
    assert.equal(body.get('grant_type'), 'refresh_token');
    assert.equal(body.get('client_id'), 'storage');
    assert.equal(body.get('client_secret'), 'secret');
    assert.equal(body.get('refresh_token'), 'old-refresh');
    assert.equal(body.get('scope'), 'openid');
    assert.equal(result.refresh_token, 'new-refresh');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('refreshToken coalesces overlapping uses of the same rotating token within one client', async () => {
  const originalFetch = globalThis.fetch;
  let releaseResponse;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Promise((resolve) => {
      releaseResponse = resolve;
    });
  };
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
    const first = auth.refreshToken({ refreshToken: 'same-refresh-token' });
    const second = auth.refreshToken({ refreshToken: 'same-refresh-token' });
    assert.equal(fetchCalls, 1);
    assert.throws(
      () => auth.refreshToken({ refreshToken: 'same-refresh-token', scope: 'openid' }),
      /different options/,
    );
    releaseResponse(
      new Response(JSON.stringify({ access_token: 'new-access', refresh_token: 'new-refresh' }), { status: 200 }),
    );
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.deepEqual(firstResult, secondResult);
    assert.equal(firstResult.refresh_token, 'new-refresh');
    assert.equal(fetchCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('public OIDC token requests omit client_secret', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(JSON.stringify({ access_token: 'access' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'native-app', clientSecret: '' });
    await auth.exchangeCode({
      code: 'authorization-code',
      codeVerifier: 'verifier',
      redirectUri: 'com.example:/callback',
    });
    await auth.refreshToken({ refreshToken: 'old-refresh' });
    for (const { options } of calls) {
      assert.equal(new URLSearchParams(options.body).has('client_secret'), false);
    }
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

test('getProfile is the session profile; getUserInfo loads OIDC UserInfo', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'test-key';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'RS256', kid: 'test-key' });
  const payload = encode({ iss: 'https://auth.example', aud: 'storage', sub: 'user', exp: 4102444800 });
  const token = `${head}.${payload}.${sign('RSA-SHA256', Buffer.from(`${head}.${payload}`), privateKey).toString('base64url')}`;
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url) === 'https://auth.example/.well-known/jwks.json') {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }
    return new Response(JSON.stringify({ id: 'user' }), { status: 200 });
  };
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
    const request = { headers: { cookie: 'connect.sid=central%20value' } };
    assert.deepEqual(await auth.getProfile(request), { id: 'user' });
    assert.equal(calls[0].url, 'https://auth.example/api/v1/profile');
    assert.equal(calls[0].options.headers.Cookie, 'connect.sid=central%20value');
    assert.equal(await auth.getSessionProfile(request).then((value) => value.id), 'user');
    assert.equal(calls[1].url, 'https://auth.example/api/v1/profile');
    assert.deepEqual(await auth.getUserInfo(token), { id: 'user' });
    assert.equal(calls[2].url, 'https://auth.example/.well-known/jwks.json');
    assert.equal(calls[3].url, 'https://auth.example/userinfo');
    assert.equal(calls[3].options.headers.Authorization, `Bearer ${token}`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('verifyToken refreshes JWKS once when a cached set lacks the token kid', async () => {
  const originalFetch = globalThis.fetch;
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'rotated-key';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'RS256', kid: 'rotated-key' });
  const payload = encode({ iss: 'https://auth.example', aud: 'storage', sub: 'user', exp: 4102444800 });
  const token = `${head}.${payload}.${sign('RSA-SHA256', Buffer.from(`${head}.${payload}`), privateKey).toString('base64url')}`;
  let jwksCalls = 0;
  globalThis.fetch = async () => {
    jwksCalls += 1;
    return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
  };
  try {
    const auth = createAuthClient({ issuer: 'https://auth.example', clientId: 'storage' });
    auth.jwks = { keys: [{ ...jwk, kid: 'old-key' }] };
    auth.jwksExpiresAt = Date.now() + 3600000;
    assert.equal((await auth.verifyToken(token)).sub, 'user');
    assert.equal(jwksCalls, 1);
    const unknownHead = encode({ alg: 'RS256', kid: 'attacker-kid' });
    await assert.rejects(auth.verifyToken(`${unknownHead}.${payload}.${token.split('.')[2]}`), /Invalid JWT signature/);
    assert.equal(jwksCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
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
