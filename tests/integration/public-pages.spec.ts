import { test, expect } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('landing page is available', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('Auth');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
  await page.goto('/me');
  await expect(page).toHaveTitle('Auth');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
});

test('login page exposes the configured sign-in method', async ({ page }) => {
  await page.goto('/login');
  if (testKey) {
    await expect(page.getByLabel('Test API key')).toBeVisible();
    await expect(page.getByText('Continue with Google')).toHaveCount(0);
    await expect(page.getByText('Use a passkey')).toHaveCount(0);
  } else {
    await expect(page.getByText('Continue with Google')).toBeVisible();
    await expect(page.getByText('Use a passkey')).toBeVisible();
    await expect(page.getByText('Approve on phone')).toBeVisible();
  }
});

test('PWA has install metadata and scanner UI', async ({ page }) => {
  await page.goto('/pwa/');
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute('href', '/pwa/manifest.webmanifest');
  await expect(page.getByRole('button', { name: 'Scan QR code' })).toBeVisible();
  const manifest = await page.request.get('/pwa/manifest.webmanifest').then((response) => response.json());
  expect(manifest.start_url).toBe('/me');
  expect(manifest.scope).toBe('/');
  const serviceWorker = await page.request.get('/pwa/sw.js');
  expect(serviceWorker.headers()['service-worker-allowed']).toBe('/');
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

  const discoveryResponse = await request.get('/.well-known/openid-configuration');
  expect(discoveryResponse.ok()).toBeTruthy();
  const discovery = await discoveryResponse.json();
  expect(new URL(discovery.jwks_uri).pathname).toBe('/.well-known/jwks.json');
});

test('profile API remains protected', async ({ request }) => {
  const response = await request.get('/profile');
  expect(response.status()).toBe(401);
});

test('account profile page redirects unauthenticated visitors to sign in', async ({ request }) => {
  const response = await request.get('/account', { maxRedirects: 0 });
  expect(response.status()).toBe(302);
  expect(response.headers().location).toBe('/login?url=%2Faccount');
});

test('test users can access application and token management', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/');
  await page.evaluate(
    async (secret) => fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } }),
    testKey,
  );
  const responses = await page.evaluate(async () =>
    Promise.all([
      fetch('/oidc/clients').then((response) => response.status),
      fetch('/api-tokens/apps').then((response) => response.status),
      fetch('/api-tokens/example').then((response) => response.status),
    ]),
  );
  expect(responses).toEqual([200, 200, 200]);
});

test('test-only session can access the dashboard sections', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/');
  const response = await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      }).then((result) => result.status),
    testKey,
  );
  expect(response).toBe(204);
  await page.goto('/');
  await expect(page.getByText('Passkeys')).toBeVisible();
  await page.goto('/me#security');
  await expect(page.getByText('Passkeys')).toBeVisible();
  await page.goto('/me#properties');
  await expect(page.getByRole('heading', { name: 'Properties' })).toBeVisible();
  await page.goto('/me#activity');
  await expect(page.getByText('Authentication history')).toBeVisible();
  await expect(page.getByTitle('Copy OIDC subject')).toBeVisible();
  await page.goto('/me#oidc');
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
});

test('profile identity and passkeys stay compact at mobile widths', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      }),
    testKey,
  );

  await page.goto('/me#security');
  await expect(page.getByText('Passkeys')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open account profile' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' })).toHaveCount(0);

  await page.setViewportSize({ width: 360, height: 800 });
  const narrowPageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(narrowPageWidth).toBeLessThanOrEqual(360);
  await page.setViewportSize({ width: 390, height: 844 });

  const layout = await page.evaluate(() => {
    const profileCard = document.querySelector('a[aria-label="Open account profile"]').getBoundingClientRect();
    const passkeys = [...document.querySelectorAll('h2')].find((item) => item.textContent.trim() === 'Passkeys');
    const section = passkeys.closest('section');
    return {
      viewportWidth: window.innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      profileCardRight: profileCard.right,
      passkeyPadding: Number.parseFloat(getComputedStyle(section).paddingTop),
    };
  });

  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.profileCardRight).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.passkeyPadding).toBeLessThanOrEqual(20);
});

test('header profile card opens a dedicated profile page with sign out', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/');
  await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      }),
    testKey,
  );

  await page.goto('/me');
  await expect(page.getByRole('button', { name: 'Sign out' })).toHaveCount(0);
  await page.getByRole('link', { name: 'Open account profile' }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole('heading', { name: 'John Doe' })).toBeVisible();
  await expect(page.getByText(/john\.doe\+.*@example\.test/)).toBeVisible();
  await expect(page.getByLabel('Administrator')).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(pageErrors).toEqual([]);
});

test('authenticated Applications section exposes app and token management', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/');
  await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      }),
    testKey,
  );
  await page.goto('/me#oidc');
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
  const app = page.locator('details').first();
  if (await app.count()) {
    await app.locator('summary').click();
    await expect(app.getByText('Scopes')).toBeVisible();
    await expect(app.getByRole('heading', { name: 'Tokens' })).toBeVisible();
  }
});

test('existing tokens load when an application is opened and only one app list is fetched', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appId = `e2e-existing-token-${Date.now()}`;
  await page.goto('/');
  await page.evaluate(
    async ({ secret, id }) => {
      await fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      });
      const app = await fetch('/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['profile'] }),
      });
      if (!app.ok) throw new Error(`Could not create test app: ${app.status}`);
      const token = await fetch(`/api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'existing test token', scopes: ['profile'] }),
      });
      if (!token.ok) throw new Error(`Could not create test token: ${token.status}`);
    },
    { secret: testKey, id: appId },
  );

  let appListRequests = 0;
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/oidc/clients' && request.method() === 'GET') appListRequests += 1;
  });
  await page.goto('/me#oidc');
  const app = page.locator('details').filter({ hasText: appId });
  await app.locator('summary').click();
  await expect(app.getByText('existing test token')).toBeVisible();
  expect(appListRequests).toBe(1);
});

test('Applications can create, show, list, revoke, and mark an API token', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appId = `e2e-token-${Date.now()}`;
  await page.goto('/');
  await page.evaluate(
    async (secret) =>
      fetch('/__test__/login', {
        method: 'POST',
        headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      }),
    testKey,
  );
  await page.goto('/me#oidc');
  await page.getByRole('button', { name: 'Add app' }).click();
  await page.getByPlaceholder('App ID').fill(appId);
  await page.getByPlaceholder('https://app.example/callback').first().fill(`https://${appId}.example/callback`);
  await page.getByRole('button', { name: 'Add' }).first().click();
  await page.getByPlaceholder('new:scope').first().fill('read:profile');
  await page.getByRole('button', { name: 'Add' }).nth(1).click();
  await page.getByRole('button', { name: 'Create app' }).click();

  const app = page.locator('details').filter({ hasText: appId });
  await app.locator('summary').click();
  await app.getByPlaceholder('Token label').fill('e2e token');
  await app.getByLabel('read:profile').check();
  await app.getByRole('button', { name: 'Generate token' }).click();
  await expect(page.locator('[data-generated-token]')).toBeVisible();
  await expect(page.locator('[data-generated-token-value]')).toContainText('auth_');
  await expect(app.getByText('e2e token')).toBeVisible();

  await page.reload();
  const reloadedApp = page.locator('details').filter({ hasText: appId });
  await reloadedApp.locator('summary').click();
  await expect(reloadedApp.getByText('e2e token')).toBeVisible();

  await reloadedApp.getByRole('button', { name: 'read:profile x' }).click();
  await expect(reloadedApp.getByText('read:profile', { exact: true })).toHaveCount(0);
  await reloadedApp.getByRole('button', { name: 'Revoke' }).click();
  await expect(reloadedApp.getByText(/^Revoked /)).toBeVisible();
  await expect(reloadedApp.getByText('Active')).toHaveCount(0);
});

test('Auth API token selector loads clients and supports create and revoke', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appId = `e2e-auth-api-${Date.now()}`;
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

  await page.evaluate(async (id) => {
    const response = await fetch('/oidc/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['storage:limits'] }),
    });
    if (!response.ok) throw new Error(`Could not create test app: ${response.status}`);
  }, appId);

  try {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') console.error(message.text());
    });
    await page.goto('/me#auth-api-tokens');
    await expect(page.getByRole('heading', { name: 'Signing keys' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Auth API tokens' })).toBeVisible();
    const selector = page.getByRole('combobox');
    await expect(selector.locator(`option[value="${appId}"]`)).toBeAttached();
    await selector.selectOption(appId);
    await expect(page.getByPlaceholder('Token label')).toBeVisible();
    await page.getByPlaceholder('Token label').fill('browser test token');
    await page.getByRole('button', { name: 'Generate Auth API token' }).click();
    expect(errors).toEqual([]);
    await expect(page.getByText('Copy now. This token is shown only once.')).toBeVisible();
    await expect(page.getByText('browser test token')).toBeVisible();
    const managementTokenText = await page.locator('.bg-emerald-50').innerText();
    const managementToken = managementTokenText.match(/auth_[A-Za-z0-9_-]+/)?.[0];
    expect(managementToken).toBeTruthy();
    const issued = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api-tokens/${encodeURIComponent(id)}/issue`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ label: 'downstream token', scopes: ['storage:limits'] }),
        });
        return { status: response.status, body: await response.json() };
      },
      { id: appId, token: managementToken! },
    );
    expect(issued.status).toBe(201);
    expect(issued.body.token).toMatch(/^auth_/);
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Revoke' }).click();
    await expect(page.getByText('revoked', { exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    await page.evaluate(async (id) => fetch(`/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }), appId);
  }
});

test('OIDC client deletion without admin access returns 403', async ({ request }) => {
  const response = await request.delete('/oidc/clients/some-client-id');
  expect(response.status()).toBe(403);
});

test('OIDC client secret regeneration without admin access returns 403', async ({ request }) => {
  const response = await request.put('/oidc/clients/some-client-id/secret', {
    json: {},
  });
  expect(response.status()).toBe(403);
});

test('admin can regenerate and delete OIDC client secret', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const secret = testKey!;
  const appId = `e2e-regenerate-${Date.now()}`;

  await page.goto('/');
  const loginStatus = await page.evaluate(async (s) => {
    const response = await fetch('/__test__/login', {
      method: 'POST',
      headers: { 'x-test-secret': s, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
    return response.status;
  }, secret);
  expect(loginStatus).toBe(204);

  const created = await page.evaluate(
    async ({ id }) => {
      const response = await fetch('/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: ['https://' + id + '.example/callback'], scopes: ['profile'] }),
      });
      if (!response.ok) throw new Error(`Create app failed: ${response.status}`);
      return response.json();
    },
    { id: appId },
  );
  try {
    const createdToken = await page.evaluate(async (id) => {
      const response = await fetch(`/api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'delete cleanup test', scopes: ['profile'] }),
      });
      if (!response.ok) throw new Error(`Create token failed: ${response.status}`);
      return response.json();
    }, appId);
    expect(createdToken.token).toBeTruthy();

    await page.goto('/me#oidc');
    await expect(page.locator('summary').filter({ hasText: appId })).toBeVisible();
    const card = page.locator('article').filter({ hasText: appId });

    const secretResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/oidc/clients/${appId}/secret` && response.request().method() === 'PUT';
    });
    page.once('dialog', (dialog) => dialog.accept());
    await card.getByRole('button', { name: 'Regenerate secret' }).click();
    const secretResponse = await secretResponsePromise;
    expect(secretResponse.status()).toBe(200);
    const regenerated = await secretResponse.json();
    expect(regenerated.secret).toBeTruthy();
    expect(regenerated.secret).not.toBe(created.secret);
    const secretBox = card.locator('.bg-emerald-50');
    await expect(secretBox).toBeVisible();
    await expect(secretBox).toContainText(regenerated.secret);

    const deleteResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/oidc/clients/${appId}` && response.request().method() === 'DELETE';
    });
    page.once('dialog', (dialog) => dialog.accept());
    await card.getByRole('button', { name: 'Delete app' }).click();
    const deleteResponse = await deleteResponsePromise;
    expect(deleteResponse.status()).toBe(204);
    await expect(card).toHaveCount(0);
    const remainingTokens = await page.evaluate(async (id) => {
      const response = await fetch(`/api-tokens/${encodeURIComponent(id)}`);
      return response.json();
    }, appId);
    expect(remainingTokens).toEqual([]);
  } finally {
    await page.evaluate(async (id) => fetch(`/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }), appId);
  }
});
