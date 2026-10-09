import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { createAuthClient } from '../assets/node.mjs';

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
    if (String(url) === 'https://auth.example/.well-known/jwks.json')
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
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
