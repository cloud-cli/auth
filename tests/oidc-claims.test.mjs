import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  isNativeRedirectUri,
  isSecureRedirectUri,
  oidcUserInfo,
  validateAuthorizationScopes,
} from '../dist/src/oidc.js';

test('OIDC authorization requires openid and only permits registered standard scopes', () => {
  assert.equal(validateAuthorizationScopes(['openid']), true);
  assert.equal(validateAuthorizationScopes(['openid', 'profile', 'email']), true);
  assert.equal(validateAuthorizationScopes(['profile']), false);
  assert.equal(validateAuthorizationScopes(['openid', 'address']), false);
});

test('UserInfo returns stable sub and profile compatibility claims only when requested', () => {
  const user = {
    userId: 'stable-user-id',
    name: 'A. User',
    email: 'a@example.test',
    photo: 'https://example.test/avatar.png',
    preferredUsername: 'a_user',
  };
  assert.deepEqual(oidcUserInfo(user, ['openid']), { sub: 'stable-user-id' });
  assert.deepEqual(oidcUserInfo(user, ['openid', 'profile', 'email']), {
    sub: 'stable-user-id',
    name: 'A. User',
    picture: 'https://example.test/avatar.png',
    photo: 'https://example.test/avatar.png',
    preferred_username: 'a_user',
    email: 'a@example.test',
  });
});

test('redirect URI validation permits HTTPS, loopback, and reverse-domain native schemes only', () => {
  assert.equal(isSecureRedirectUri('https://app.example/callback'), true);
  assert.equal(isSecureRedirectUri('http://127.0.0.1:49152/callback'), true);
  assert.equal(isSecureRedirectUri('http://app.example/callback'), false);
  assert.equal(isNativeRedirectUri('com.example.app:/oauth2redirect'), true);
  assert.equal(isNativeRedirectUri('mailto:user@example.test'), false);
  assert.equal(isNativeRedirectUri('https://app.example/callback'), false);
});
