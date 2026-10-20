import { createLocalJWKSet, jwtVerify } from 'jose';
import { expect, test } from '@playwright/test';
import { createAdminFixture, deleteAdminFixture } from './agent-fixture.js';

const audience = 'https://rotation-test.example';

test('rotated JWTs use the active key and retiring keys still verify old tokens', async ({ page }) => {
  test.skip(process.env.JWT_ROTATION_TESTS !== 'true', 'Requires a signing-enabled JWT rotation test instance');
  const fixture = await createAdminFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
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

    const getAccessToken = () =>
      page.evaluate(async (tokenAudience) => {
        const response = await fetch('/api/v1/session/token', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ audience: tokenAudience }),
        });
        if (!response.ok) throw new Error(`Could not issue session token (${response.status}).`);
        return (await response.json()).access_token as string;
      }, audience);

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
    const jwksResponse = await page.request.get('/.well-known/jwks.json');
    expect(jwksResponse.status()).toBe(200);
    const jwks = await jwksResponse.json();
    expect(afterKid).not.toBe(beforeKid);
    expect(jwks.keys.map((key: { kid: string }) => key.kid)).toContain(beforeKid);
    expect(jwks.keys.map((key: { kid: string }) => key.kid)).toContain(afterKid);
    const keySet = createLocalJWKSet(jwks);
    const issuer = new URL(process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000').origin;
    await jwtVerify(before, keySet, { issuer, audience });
    await jwtVerify(after, keySet, { issuer, audience });
  } finally {
    await deleteAdminFixture(page, fixture);
  }
});
