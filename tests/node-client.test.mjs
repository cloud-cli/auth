import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthClient } from '../assets/node.mjs';

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
