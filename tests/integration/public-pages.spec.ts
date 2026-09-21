import { test, expect } from '@playwright/test';

test('landing page is available', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('Apphor Auth');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
});

test('login page exposes supported sign-in methods', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByText('Continue with Google')).toBeVisible();
  await expect(page.getByText('Use a passkey')).toBeVisible();
  await expect(page.getByText('Approve on phone')).toBeVisible();
});

test('PWA has install metadata and scanner UI', async ({ page }) => {
  await page.goto('/pwa/');
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute('href', '/pwa/manifest.webmanifest');
  await expect(page.getByRole('button', { name: 'Scan QR code' })).toBeVisible();
});

test('public modules and OpenAPI are served', async ({ request }) => {
  for (const path of ['/index.mjs', '/dashboard.mjs', '/node.mjs']) {
    const response = await request.get(path);
    expect(response.ok(), path).toBeTruthy();
  }

  const response = await request.get('/api');
  expect(response.ok()).toBeTruthy();
  const spec = await response.json();
  expect(spec.openapi).toBe('3.1.0');
  expect(spec.paths['/authorize']).toBeDefined();
  expect(spec.paths['/oauth/introspect']).toBeDefined();
});

test('profile API remains protected', async ({ request }) => {
  const response = await request.get('/profile');
  expect(response.status()).toBe(401);
});

test('test-only session can access the dashboard sections', async ({ page }) => {
  test.skip(!process.env.AUTH_TEST_SECRET, 'Requires a test-enabled deployment');
  await page.goto('/');
  const response = await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } }).then(
        (result) => result.status,
      ),
    process.env.AUTH_TEST_SECRET,
  );
  expect(response).toBe(204);
  await page.goto('/me#security');
  await expect(page.getByText('Passkeys')).toBeVisible();
  await page.goto('/me#properties');
  await expect(page.getByRole('heading', { name: 'Properties' })).toBeVisible();
  await page.goto('/me#activity');
  await expect(page.getByText('Authentication history')).toBeVisible();
  await page.goto('/me#oidc');
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
});

test('authenticated Applications section exposes app and token management', async ({ page }) => {
  test.skip(!process.env.AUTH_TEST_SECRET, 'Requires a test-enabled deployment');
  await page.goto('/');
  await page.evaluate(
    async (secret) => fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } }),
    process.env.AUTH_TEST_SECRET,
  );
  await page.goto('/me#oidc');
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
  const app = page.locator('details').first();
  if (await app.count()) {
    await app.locator('summary').click();
    await expect(app.getByText('Scopes')).toBeVisible();
    await expect(app.getByText('Tokens')).toBeVisible();
  }
});
