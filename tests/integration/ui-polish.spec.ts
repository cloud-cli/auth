import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('account brand mark and OIDC application spacing and borders', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');

  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', {
      method: 'POST',
      headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
  }, testKey);

  const appId = `e2e-ui-${Date.now()}`;
  await page.goto('/account');
  await expect(page.locator('header a[href="/me"] svg')).toBeVisible();

  await page.evaluate(async (id) => {
    const response = await fetch('/api/v1/oidc/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['profile'] }),
    });
    if (!response.ok) throw new Error(`Could not create test app: ${response.status}`);
  }, appId);

  try {
    await page.goto('/me#oidc');
    const appDetails = page.locator('details').filter({ hasText: appId });
    const appRow = appDetails.locator('xpath=..');
    await expect(appRow).toHaveCSS('border-top-color', 'rgba(0, 0, 0, 0)');
    await appDetails.locator('summary').click();
    await expect(appRow).toHaveCSS('border-top-color', 'rgb(226, 232, 240)');

    const callbackForm = appDetails.locator('form').first();
    const marginTop = await callbackForm.evaluate((element) => Number.parseFloat(getComputedStyle(element).marginTop));
    expect(marginTop).toBe(24);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
});
