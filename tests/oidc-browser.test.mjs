import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createOidcClient } from '../assets/oidc.mjs';

test('session heartbeat distinguishes unauthorized from unavailable and checks the app session separately', async () => {
  const responses = [new Response(null, { status: 401 }), new Response(null, { status: 503 })];
  const client = createOidcClient({
    issuer: 'https://auth.example',
    fetch: async () => responses.shift(),
    heartbeatInterval: 5000,
  });
  await client.start();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(client.getState().status, 'unauthenticated');
  await client.stop();

  const unavailableClient = createOidcClient({
    issuer: 'https://auth.example',
    fetch: async () => new Response(null, { status: 503 }),
  });
  await unavailableClient.start();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(unavailableClient.getState().status, 'unavailable');
  assert.equal(unavailableClient.isAuthenticated(), false);
  unavailableClient.stop();
});

test('token requests use credentials, deduplicate per audience, and distinguish configuration errors', async () => {
  const calls = [];
  const client = createOidcClient({
    issuer: 'https://auth.example',
    fetch: async (url, options) => {
      calls.push({ url: String(url), options });
      await new Promise((resolve) => setTimeout(resolve, 0));
      return new Response(JSON.stringify({ access_token: 'short-lived', expires_in: 60 }), { status: 200 });
    },
  });
  const [first, second] = await Promise.all([client.getAccessToken('api'), client.getAccessToken('api')]);
  assert.equal(first, 'short-lived');
  assert.equal(second, first);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://auth.example/api/v1/session/token');
  assert.equal(calls[0].options.credentials, 'include');
  assert.deepEqual(JSON.parse(calls[0].options.body), { audience: 'api' });

  const denied = createOidcClient({
    issuer: 'https://auth.example',
    fetch: async () => new Response(null, { status: 403 }),
  });
  await assert.rejects(denied.getAccessToken('api'), { code: 'TOKEN_CONFIGURATION_ERROR' });
});

test('successful Auth session does not imply a valid relying-party session', async () => {
  const client = createOidcClient({
    issuer: 'https://auth.example',
    rpSessionCheck: async () => false,
    fetch: async (_url, options) => {
      assert.equal(options.method, 'HEAD');
      return new Response(null, { status: 204 });
    },
  });
  await client.start();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(client.isAuthenticated(), true);
  assert.equal(client.getState().relyingPartySession, 'unauthenticated');
  client.stop();
});
