import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('v2 navigation, profile, and dashboard sections render cleanly', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/');
  const login = await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: secret, role: 'admin' }),
      }).then((response) => response.status),
    testKey,
  );
  expect(login).toBe(204);

  await page.goto('/me');
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await expect(page.locator('#nav-menu')).toBeVisible();
  await expect(page.locator('#sidebar').getByText('auth', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Profile' })).toBeVisible();

  for (const [hash, heading] of [
    ['security', 'Passkeys'],
    ['profile', 'Your profile'],
    ['properties', 'Properties'],
    ['activity', 'Authentication history'],
    ['oidc', 'Applications'],
    ['auth-api-tokens', 'Signing keys'],
  ]) {
    await page.goto(`/me#${hash}`);
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  }
});
