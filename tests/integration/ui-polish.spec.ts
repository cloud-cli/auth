import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('account and dashboard brand marks are violet; OIDC application spacing and borders are correct', async ({
  page,
}) => {
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
  const accountHeader = page.locator('main > header');
  await expect(accountHeader).toHaveCSS('border-bottom-width', '0px');
  await expect(accountHeader).toHaveCSS('padding-bottom', '0px');
  const accountBrand = page.locator('header a[href="/me"] svg');
  await expect(accountBrand).toBeVisible();
  await expect(accountBrand).toHaveCSS('color', 'rgb(114, 87, 245)');
  await expect(accountBrand.locator('xpath=..')).toHaveCSS('font-size', '18px');
  await page.goto('/me');
  const header = page.locator('main > header');
  await expect(header).toHaveCSS('border-bottom-width', '0px');
  await expect(header).toHaveCSS('padding-bottom', '0px');
  await expect(page.locator('header a[href="/account"]')).toHaveCSS('padding', '8px');
  const dashboardBrand = page.locator('header a[href="/me"] svg');
  await expect(dashboardBrand).toBeVisible();
  await expect(dashboardBrand).toHaveCSS('color', 'rgb(114, 87, 245)');
  await expect(dashboardBrand.locator('xpath=..')).toHaveCSS('font-size', '18px');
  const nav = page.locator('auth-nav nav');
  await expect(nav).toHaveCSS('justify-content', 'center');
  await expect(nav).toHaveCSS('border-bottom-width', '1px');
  await expect(page.locator('auth-nav a[href="/me#security"]')).toHaveClass(/rounded-md/);
  for (const [section, selector] of [
    ['security', 'dashboard-security section'],
    ['properties', 'dashboard-properties section'],
    ['activity', 'dashboard-activity section'],
    ['oidc', 'dashboard-oidc section'],
    ['auth-api-tokens', 'signing-key-manager section'],
    ['auth-api-tokens', 'dashboard-auth-api-tokens section'],
  ]) {
    await page.goto(`/me#${section}`);
    const pageSection = page.locator(selector);
    await expect(pageSection).toHaveClass(/rounded-b-lg/);
    await expect(pageSection).not.toHaveClass(/mt-/);
  }

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
    const callbackSectionMargin = await callbackForm.evaluate((element) => {
      let current = element.parentElement;
      while (current && !current.querySelector('strong')?.textContent?.includes('Callback URLs')) {
        current = current.parentElement;
      }
      return Number.parseFloat(getComputedStyle(current!).marginTop);
    });
    expect(callbackSectionMargin).toBe(20);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
});
