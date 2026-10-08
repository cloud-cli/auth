import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('Auth API token overview lists minted tokens with their app before selection', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appIds = [`e2e-token-overview-a-${Date.now()}`, `e2e-token-overview-b-${Date.now()}`];

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

  await page.evaluate(async (ids) => {
    for (const id of ids) {
      const client = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['profile'] }),
      });
      if (!client.ok) throw new Error('Could not create a test OIDC client');
      const token = await fetch(`/api/v1/auth-api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: `token for ${id}` }),
      });
      if (!token.ok) throw new Error('Could not create a test Auth API token');
    }
  }, appIds);

  try {
    await page.goto('/me#auth-api-tokens');
    await expect(page.getByText('Previously minted tokens across all apps')).toBeVisible();
    for (const id of appIds) {
      await expect(page.getByText(`token for ${id}`, { exact: true })).toBeVisible();
      await expect(page.getByText(`App: ${id}`, { exact: true })).toBeVisible();
    }

    const selector = page.getByRole('combobox');
    await expect(selector).toHaveValue('');
    await expect(page.getByPlaceholder('Token label')).toHaveCount(0);
    await selector.selectOption(appIds[0]);
    await expect(page.getByPlaceholder('Token label')).toBeVisible();
    await expect(page.getByText(`token for ${appIds[0]}`, { exact: true })).toBeVisible();
  } finally {
    for (const id of appIds) {
      await page.evaluate(
        async (clientId) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(clientId)}`, { method: 'DELETE' }),
        id,
      );
    }
  }
});
