import { expect, test } from '@playwright/test';

const authLabKey = process.env.AUTH_LAB_KEY;

test('token scope editor opens, cancels, and saves on the Auth Lab deployment', async ({ page }) => {
  test.skip(!authLabKey, 'Requires AUTH_LAB_KEY');
  const appId = `e2e-scope-editor-${Date.now()}`;
  let clientCreated = false;

  try {
    await page.goto('/');
    const loginStatus = await page.evaluate(async (key) => {
      const response = await fetch('/__test__/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key, role: 'admin' }),
      });
      return response.status;
    }, authLabKey);
    expect(loginStatus).toBe(204);

    const createStatus = await page.evaluate(async (id) => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id,
          redirectUris: [`https://${id}.example/callback`],
          scopes: ['workflows:read', 'artifacts:read'],
        }),
      });
      return response.status;
    }, appId);
    expect(createStatus).toBe(201);
    clientCreated = true;

    const tokenStatus = await page.evaluate(async (id) => {
      const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'scope editor test', scopes: ['workflows:read', 'artifacts:read'] }),
      });
      return response.status;
    }, appId);
    expect(tokenStatus).toBe(201);

    await page.goto('/me#applications');
    const appDetails = page.locator('details').filter({ hasText: appId });
    await appDetails.locator('summary').click();

    const tokenCard = page.locator('article').filter({ hasText: 'scope editor test' });
    await tokenCard.getByRole('button', { name: 'Edit scopes' }).click();
    await expect(tokenCard.getByText('Token scopes')).toBeVisible();
    await tokenCard.getByRole('button', { name: 'Cancel' }).click();
    await expect(tokenCard.getByText('Token scopes')).toBeHidden();

    await tokenCard.getByRole('button', { name: 'Edit scopes' }).click();
    await expect(tokenCard.getByText('Token scopes')).toBeVisible();
    await tokenCard.getByLabel('artifacts:read').uncheck();
    await tokenCard.getByRole('button', { name: 'Save scopes' }).click();
    await expect(tokenCard.getByText('Scopes: workflows:read', { exact: true })).toBeVisible();
    await expect(tokenCard.getByText('Token scopes')).toBeHidden();
  } finally {
    if (clientCreated) {
      await page.evaluate(async (id) => {
        await fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' });
      }, appId);
    }
  }
});
