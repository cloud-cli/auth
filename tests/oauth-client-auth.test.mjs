import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseBasicClientCredentials } from '../dist/src/oauth-client-auth.js';

test('parses RFC 6749 Basic credentials with form-encoded client ID and secret', () => {
  const clientId = 'flow.api.apphor.de';
  const clientSecret = 'secret+with/special=characters';
  const formEncode = (value) =>
    encodeURIComponent(value)
      .replace(/[-_.!~*'()]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`)
      .replace(/%20/g, '+');
  const encoded = `${formEncode(clientId)}:${formEncode(clientSecret)}`;
  const authorization = `Basic ${Buffer.from(encoded).toString('base64')}`;

  assert.deepEqual(parseBasicClientCredentials(authorization), { clientId, clientSecret });
});

test('accepts existing Basic credentials when no form escaping is needed', () => {
  const authorization = `Basic ${Buffer.from('runner:base64url-secret').toString('base64')}`;

  assert.deepEqual(parseBasicClientCredentials(authorization), {
    clientId: 'runner',
    clientSecret: 'base64url-secret',
  });
});

test('rejects malformed Basic credentials', () => {
  assert.equal(parseBasicClientCredentials('Bearer token'), null);
  assert.equal(parseBasicClientCredentials(`Basic ${Buffer.from('missing-separator').toString('base64')}`), null);
  assert.equal(parseBasicClientCredentials(`Basic ${Buffer.from('client:%ZZ').toString('base64')}`), null);
});
