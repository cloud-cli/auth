import { createLocalJWKSet, jwtVerify } from 'jose';
import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];
const audience = 'https://rotation-test.example';

test('rotated JWTs use the active kid and retiring keys still verify old tokens', async ({ page }) => {
  test.skip(!testKey || process.env.JWT_ROTATION_TESTS !== 'true', 'Requires a test-enabled JWT signing deployment');
  const issuer = new URL(process.env.INTEGRATION_BASE_URL || 'http://localhost:3000').origin;
  await page.goto('/');
  const loginStatus = await page.evaluate(async (secret) => {
    const response = await fetch('/__test__/login', {
      method: 'POST',
      headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
    return response.status;
  }, testKey);
  expect(loginStatus).toBe(204);

  const getAccessToken = async () =>
    page.evaluate(async (tokenAudience) => {
      const response = await fetch('/api/v1/session/token', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ audience: tokenAudience }),
      });
      if (!response.ok) throw new Error(`Could not issue session token: ${response.status}`);
      return (await response.json()).access_token as string;
    }, audience);
  const bootstrapStatus = await page.evaluate(
    async () =>
      (
        await fetch('/api/v1/keys/rotate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        })
      ).status,
  );
  expect(bootstrapStatus).toBe(201);
  const before = await getAccessToken();
  const beforeKid = JSON.parse(Buffer.from(before.split('.')[0], 'base64url').toString()).kid;
  const rotateStatus = await page.evaluate(
    async () =>
      (
        await fetch('/api/v1/keys/rotate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        })
      ).status,
  );
  expect(rotateStatus).toBe(201);

  const after = await getAccessToken();
  const afterKid = JSON.parse(Buffer.from(after.split('.')[0], 'base64url').toString()).kid;
  const jwks = await page.request.get('/.well-known/jwks.json').then((response) => response.json());
  expect(afterKid).not.toBe(beforeKid);
  expect(jwks.keys.map((key: { kid: string }) => key.kid)).toContain(beforeKid);
  expect(jwks.keys.map((key: { kid: string }) => key.kid)).toContain(afterKid);
  const keySet = createLocalJWKSet(jwks);
  await jwtVerify(before, keySet, { issuer, audience });
  await jwtVerify(after, keySet, { issuer, audience });
});
