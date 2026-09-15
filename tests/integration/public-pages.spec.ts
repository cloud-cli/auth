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
