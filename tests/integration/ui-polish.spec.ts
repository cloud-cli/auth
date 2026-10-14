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

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/me');
  await expect(page.locator('html')).toHaveClass(/dark/);
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await expect(page.locator('#nav-menu')).toBeVisible();
  await expect(page.locator('#sidebar').getByText('auth', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Profile' })).toBeVisible();
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
  await expect(page.locator('#sidebar')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
  await expect(page.locator('main > header')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
  await expect(page.locator('main > header')).toHaveCSS('border-bottom-width', '0px');
  const securityNavLink = page.locator('#sidebar button[data-target="security"]');
  await expect(securityNavLink).toHaveCSS('background-color', 'rgb(28, 42, 32)');
  await expect(securityNavLink).toHaveCSS('color', 'rgb(215, 237, 200)');
  await page.getByRole('button', { name: 'Add passkey' }).hover();
  await expect(page.getByRole('button', { name: 'Add passkey' })).toHaveCSS('background-color', 'rgb(47, 86, 59)');
  await expect(page.locator('main > div.bg-white')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
  await expect(page.locator('#theme-toggle')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
  await page.goto('/me#profile');
  await expect(page.locator('.v2-profile-identity')).toHaveCSS('background-color', 'rgb(25, 37, 29)');

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

test('theme toggle follows system preference and persists explicit choice', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.emulateMedia({ colorScheme: 'dark' });
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
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('html')).toHaveClass(/dark/);
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
  const toggle = page.getByRole('button', { name: 'Switch to light theme' });
  await expect(toggle).toBeVisible();
  await expect(page.locator('header lucide-icon[icon="chevron-down"]')).toHaveCount(0);

  await toggle.click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('html')).not.toHaveClass(/dark/);
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(238, 242, 236)');
  await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('auth-theme'))).toBe('light');

  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('html')).not.toHaveClass(/dark/);
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(238, 242, 236)');
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('html')).toHaveClass(/dark/);
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
  await page.evaluate(() => localStorage.removeItem('auth-theme'));
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByRole('button', { name: 'Switch to light theme' })).toBeVisible();
});
