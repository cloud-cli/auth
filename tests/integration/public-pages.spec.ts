import { test, expect } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

async function allowLocalLi3Imports(page: import('@playwright/test').Page) {
  const baseURL = process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000';
  if (new URL(baseURL).hostname !== '127.0.0.1') {
    return;
  }

  await page.route('https://cdn.li3.dev/**', async (route) => {
    const response = await route.fetch({
      headers: { ...route.request().headers(), origin: 'https://auth.lab.apphor.de' },
    });
    await route.fulfill({
      response,
      headers: { ...response.headers(), 'access-control-allow-origin': '*' },
    });
  });
}

test('landing page is available', async ({ page }) => {
  await allowLocalLi3Imports(page);
  await page.goto('/');
  await expect(page).toHaveTitle('Auth');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
  await page.goto('/me');
  await expect(page).toHaveTitle('Auth');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(16, 23, 19)');
  await expect(page.getByTestId('landing-card')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
});

test('login uses the forest and mint sign-in presentation', async ({ page }) => {
  await allowLocalLi3Imports(page);
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'A single auth for every app.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.locator('body')).toHaveAttribute('data-page', 'login');
  await expect(page.locator('body')).toHaveAttribute('data-test-login', /^(true|false)$/);
  if (testKey) {
    await expect(page.getByLabel('Test API key')).toBeVisible();
    const signIn = page.getByRole('button', { name: 'Sign in' });
    await expect(signIn).toBeVisible();
    await expect(signIn).toHaveCSS('background-color', 'rgb(38, 61, 50)');
  } else {
    await expect(page.getByRole('link', { name: 'Continue with Google' })).toBeVisible();
    const passkey = page.getByRole('link', { name: 'Use a passkey' });
    await expect(passkey).toBeVisible();
    await expect(passkey).toHaveCSS('background-color', 'rgb(38, 61, 50)');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(16, 23, 19)');
  await expect(page.getByTestId('login-card')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
  if (!testKey) {
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Use a passkey' })).toBeFocused();
    await expect(page.getByRole('link', { name: 'Use a passkey' })).toHaveCSS('color', 'rgb(255, 255, 255)');
  }
  expect(pageErrors).toEqual([]);
});

test('passkey action stays legible on keyboard focus in either color scheme', async ({ page }) => {
  await allowLocalLi3Imports(page);
  await page.goto('/login');
  await page.locator('body').evaluate((body) => {
    const passkey = document.createElement('a');
    passkey.className =
      'flex min-h-12 items-center justify-center gap-2 rounded-xl bg-brand px-4 font-bold text-accent transition hover:bg-[#1a2a22] hover:shadow-md focus-visible:bg-[#376d46] focus-visible:text-white focus-visible:outline focus-visible:outline-[3px] focus-visible:outline-offset-[3px] focus-visible:outline-accent focus-visible:ring-2 focus-visible:ring-accent dark:focus-visible:outline-[#c8e6a8]';
    passkey.href = '#passkey-focus-test';
    passkey.textContent = 'Use a passkey';
    body.prepend(passkey);
  });
  const passkey = page.getByRole('link', { name: 'Use a passkey' });
  await page.keyboard.press('Tab');
  await expect(passkey).toBeFocused();
  await expect(passkey).toHaveCSS('color', 'rgb(255, 255, 255)');
  await expect(passkey).toHaveCSS('background-color', 'rgb(55, 109, 70)');

  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(passkey).toHaveCSS('color', 'rgb(255, 255, 255)');
  await expect(passkey).toHaveCSS('background-color', 'rgb(55, 109, 70)');
  await expect(passkey).toHaveCSS('outline-color', 'rgb(200, 230, 168)');
});

test('legacy v2 route is removed while dashboard components remain available', async ({ request }) => {
  const legacyRoute = await request.get('/v2');
  expect(legacyRoute.status()).toBe(404);

  const pageResponse = await request.get('/ui/v2.html');
  expect(pageResponse.ok()).toBeTruthy();
  const page = await pageResponse.text();
  expect(page).toContain('<v2-layout class="block h-full w-full"></v2-layout>');
  expect(page).not.toContain('Management /');

  for (const asset of [
    'dashboard-layout.html',
    'dashboard-security.html',
    'dashboard-properties.html',
    'dashboard-applications.html',
    'dashboard-app-editor.html',
    'dashboard-app-form.html',
    'dashboard-users.html',
    'dashboard-keys.html',
    'dashboard-activity.html',
    'dashboard-profile.html',
    'dashboard-copy-value.html',
  ]) {
    const response = await request.get(`/ui/${asset}`);
    expect(response.ok(), `/ui/${asset}`).toBeTruthy();
    const component = await response.text();
    expect(component).toContain('<template component=');
    expect(component, `${asset} setup should export a component factory`).toContain('export default function () {');
  }

  const layout = await request.get('/ui/dashboard-layout.html').then((response) => response.text());
  expect(layout).not.toContain('Flow Auth Server v2.4.1');
  expect(layout).not.toContain('border-r border-gray-200/50');
});

test('default dashboard loads v2 profile and admin user details', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await allowLocalLi3Imports(page);
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: secret }),
    });
  }, testKey!);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await page.goto('/me');
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  const profile = await page.evaluate(async () => (await fetch('/api/v1/profile')).json());
  await expect(page.locator('header').getByText(profile.name, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Users' }).click();
  const user = page.getByRole('list').getByText(profile.email, { exact: true });
  await expect(user).toBeVisible();
  await user.click();
  await expect(page.getByText('UUID:', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Profile' }).click();
  await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
  const usernameInput = page.locator('#v2-preferred-username');
  if (await usernameInput.count()) {
    await expect(usernameInput).toBeVisible();
  } else {
    await expect(page.getByText('Saved username:')).toBeVisible();
  }
  await expect(page.getByText('OIDC subject', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy OIDC subject' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

  const propertyKey = `v2-clientSecret-${Date.now()}`;
  await page.getByRole('button', { name: 'Properties' }).click();
  await page.getByPlaceholder('Key').fill(propertyKey);
  await page.getByPlaceholder('Value').fill('v2-e2e-value');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  const propertyRow = page.locator('div.flex.items-center.gap-3').filter({ hasText: propertyKey });
  const propertyValue = propertyRow.locator('input[readonly]');
  await expect(propertyValue).toHaveValue('v2-e2e-value');
  await expect(propertyRow.getByRole('button', { name: 'Copy value' })).toHaveCount(0);
  expect(await propertyValue.evaluate((input) => getComputedStyle(input).filter)).toBe('none');
  page.once('dialog', (dialog) => dialog.accept());
  await propertyRow.getByRole('button', { name: 'Remove property' }).click();
  await expect(page.getByText(propertyKey, { exact: true })).toHaveCount(0);

  const clientId = `v2-dashboard-${Date.now()}`;
  try {
    await page.getByRole('button', { name: 'Applications' }).click();
    await page.getByRole('button', { name: 'Add app' }).click();
    const appForm = page.locator('v2-app-form');
    await appForm.getByPlaceholder('App ID').fill(clientId);
    await appForm.getByPlaceholder('https://app.example/callback').fill(`https://${clientId}.example/callback`);
    await appForm.getByRole('button', { name: 'Add', exact: true }).first().click();
    await appForm.getByPlaceholder('new:scope').fill('profile');
    await appForm.getByRole('button', { name: 'Add', exact: true }).last().click();
    await appForm.getByRole('button', { name: 'Create app' }).click();
    await expect(page.getByText('Copy this new client secret now. It is only shown once.')).toBeVisible();

    const application = page.locator('details').filter({ hasText: clientId });
    await expect(application).toBeVisible();
    const applicationRow = page.getByRole('listitem').filter({ hasText: clientId });
    await application.locator('summary').click();
    await expect(applicationRow.getByText('Callback URLs', { exact: true })).toBeVisible();
    await expect(applicationRow.getByText('Post-logout return URLs', { exact: true })).toBeVisible();
    await expect(applicationRow.getByText('Scopes', { exact: true })).toBeVisible();
    await expect(applicationRow.getByRole('heading', { name: 'Tokens' })).toBeVisible();

    await page.getByRole('button', { name: 'Activity' }).click();
    const auditOptions = await page.evaluate(async () =>
      fetch('/api/v1/audit/options').then((response) => response.json()),
    );
    if (auditOptions.apps.length && auditOptions.events.length) {
      const app = auditOptions.apps[0];
      const event = auditOptions.events[0];
      const [appFilter, eventFilter] = await page.getByRole('combobox').all();
      await appFilter.selectOption({ label: app });
      await eventFilter.selectOption({ label: event });
      const filteredResponse = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return (
          url.pathname === '/api/v1/audit' &&
          url.searchParams.get('app') === app &&
          url.searchParams.get('event') === event
        );
      });
      await page.getByRole('button', { name: 'Filter' }).click();
      expect((await filteredResponse).ok()).toBeTruthy();
    }
  } finally {
    const status = await page.evaluate(
      async (id) =>
        fetch('/api/v1/oidc/clients/' + encodeURIComponent(id), { method: 'DELETE' }).then(
          (response) => response.status,
        ),
      clientId,
    );
    expect([204, 404]).toContain(status);
  }
});

test('session-dependent app entry is not cached or conditionally revalidated', async ({ request }) => {
  const response = await request.get('/me', { headers: { 'if-none-match': '*' } });
  expect(response.status()).toBe(200);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers().vary).toContain('Cookie');
});

test('a stale duplicate session cookie cannot shadow a newly authenticated session', async ({ page, context }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/login');
  await page.getByLabel('Test API key').fill(testKey!);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/me$/);

  const sessionCookie = (await context.cookies()).find((cookie) => cookie.name === 'connect.sid');
  expect(sessionCookie).toBeDefined();
  const origin = new URL(page.url());
  await context.addCookies([
    {
      name: 'connect.sid',
      value: 'stale-session',
      domain: origin.hostname,
      path: '/me',
      httpOnly: true,
      secure: origin.protocol === 'https:',
      sameSite: 'Lax',
    },
  ]);

  await page.goto('/me');
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
});

test('login page exposes the configured sign-in method', async ({ page }) => {
  await page.goto('/login');
  const alternatives = page.getByText('Try another way', { exact: true });
  if (testKey) {
    await expect(alternatives).toHaveCount(0);
    await expect(page.getByLabel('Test API key')).toBeVisible();
    await expect(page.getByText('Continue with Google')).toHaveCount(0);
    await expect(page.getByText('Use a passkey')).toHaveCount(0);
    await page.getByLabel('Test API key').fill(testKey);
    const testLoginResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/__test__/login' && response.request().method() === 'POST',
    );
    const profileResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/api/v1/profile' && response.request().method() === 'GET',
    );
    await page.getByRole('button', { name: 'Sign in' }).click();
    expect((await testLoginResponse).status(), 'test-key login endpoint response').toBe(204);
    expect((await profileResponse).status(), 'profile response after test-key login').toBe(200);
    await expect(page).toHaveURL(/\/me$/);
    await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  } else {
    await expect(alternatives).toBeVisible();
    await expect(page.getByText('Continue with Google')).toBeVisible();
    await expect(page.getByText('Use a passkey')).toBeVisible();
    await expect(page.getByText('Approve on phone')).toBeHidden();
    await expect(page.getByText('Use a recovery code')).toBeHidden();
    await alternatives.click();
    await expect(page.getByText('Approve on phone')).toBeVisible();
    await expect(page.getByText('Use a recovery code')).toBeVisible();
  }
});

test('PWA has install metadata and scanner UI', async ({ page }) => {
  await page.goto('/pwa/');
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute('href', '/ui/manifest.webmanifest');
  await expect(page.getByRole('button', { name: 'Scan QR code' })).toBeVisible();
  const manifest = await page.request.get('/ui/manifest.webmanifest').then((response) => response.json());
  expect(manifest.start_url).toBe('/me');
  expect(manifest.scope).toBe('/');
  const serviceWorker = await page.request.get('/ui/sw.js');
  expect(serviceWorker.headers()['content-type']).toContain('javascript');
  expect(serviceWorker.headers()['service-worker-allowed']).toBe('/');
});

test('public modules and OpenAPI are served', async ({ request }) => {
  for (const path of ['/index.mjs', '/node.mjs', '/ui/dashboard.mjs', '/ui/lib.mjs', '/ui/embed.html']) {
    const response = await request.get(path);
    expect(response.ok(), path).toBeTruthy();
  }

  const response = await request.get('/api');
  expect(response.ok()).toBeTruthy();
  const spec = await response.json();
  expect(spec.openapi).toBe('3.1.0');
  expect(spec.paths['/authorize']).toBeDefined();
  expect(spec.paths['/oauth/introspect']).toBeDefined();
  expect(spec.paths['/index.mjs']).toBeDefined();
  expect(spec.paths['/node.mjs']).toBeDefined();
  expect(spec.paths['/api/v1/profile']).toBeDefined();
  expect(spec.paths['/api/v1/revoke']).toBeDefined();
  expect(spec.paths['/revoke']).toBeDefined();
  expect(spec.paths['/profile']).toBeUndefined();
  expect(spec.paths['/dashboard.mjs']).toBeUndefined();
  expect(spec.paths['/ui/dashboard.mjs']).toBeUndefined();

  const discoveryResponse = await request.get('/.well-known/openid-configuration');
  expect(discoveryResponse.ok()).toBeTruthy();
  const discovery = await discoveryResponse.json();
  expect(new URL(discovery.jwks_uri).pathname).toBe('/.well-known/jwks.json');
  expect(new URL(discovery.end_session_endpoint).pathname).toBe('/logout');
  expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
  expect(discovery.claims_supported).toContain('sub');
  expect(discovery.scopes_supported).toContain('offline_access');
  expect(discovery.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
  expect(new URL(discovery.revocation_endpoint).pathname).toBe('/revoke');
  expect(discovery.token_endpoint_auth_methods_supported).toEqual(['client_secret_post', 'none']);
});

test('profile API remains protected', async ({ request }) => {
  const response = await request.get('/api/v1/profile');
  expect(response.status()).toBe(401);
});

test('admin-only page errors use the branded sign-in experience', async ({ request }) => {
  const response = await request.get('/oidc', { headers: { accept: 'text/html' } });
  expect(response.status()).toBe(403);
  const body = await response.text();
  expect(body).toContain('Welcome back');
  expect(body).toContain('Sign in with an administrator account to continue.');
  expect(body).not.toContain('{"error"');
});

test('invalid browser authorization and logout states use the branded error page', async ({ request }) => {
  for (const path of [
    '/authorize',
    '/logout?client_id=missing&post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout',
  ]) {
    const response = await request.get(path, { headers: { accept: 'text/html' } });
    expect(response.status()).toBe(400);
    const body = await response.text();
    expect(body).toContain('<!doctype html>');
    expect(body).toContain('role="alert"');
    expect(body).toContain('Welcome back');
    expect(body).toContain('Try signing in again');
    expect(body).toContain('Return to Auth home');
  }
});

test('invalid authorization requests return actionable OAuth errors to registered apps', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const clientId = `e2e-auth-error-${Date.now()}`;
  const redirectUri = 'https://auth-error.example/callback';
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } });
  }, testKey);
  const created = await page.evaluate(
    async ({ id, uri }) => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: [uri] }),
      });
      return response.status;
    },
    { id: clientId, uri: redirectUri },
  );
  expect(created).toBe(201);
  try {
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      state: 'retry-state',
      code_challenge: 'invalid',
      code_challenge_method: 'S256',
      scope: 'openid',
    });
    const response = await page.request.get(`/authorize?${query}`, { maxRedirects: 0 });
    expect(response.status()).toBe(302);
    const callback = new URL(response.headers().location);
    expect(callback.origin + callback.pathname).toBe(redirectUri);
    expect(callback.searchParams.get('error')).toBe('invalid_request');
    expect(callback.searchParams.get('state')).toBe('retry-state');
    expect(callback.searchParams.get('error_description')).toContain('Start a new sign-in');

    const legacyQuery = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      state: 'legacy-state',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
    });
    const legacyResponse = await page.request.get(`/authorize?${legacyQuery}`, { maxRedirects: 0 });
    expect(legacyResponse.status()).toBe(302);
    const legacyCallback = new URL(legacyResponse.headers().location);
    expect(legacyCallback.origin + legacyCallback.pathname).toBe(redirectUri);
    expect(legacyCallback.searchParams.has('code')).toBe(true);
    expect(legacyCallback.searchParams.get('state')).toBe('legacy-state');
    expect(legacyCallback.searchParams.has('error')).toBe(false);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      clientId,
    );
  }
});

test('admin Users page lists accounts and protects the current administrator', async ({ page, request }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  expect((await request.get('/api/v1/admin/users')).status()).toBe(403);
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } });
  }, testKey);
  await page.goto('/me#users');
  await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
  await expect(page.locator('#nav-menu lucide-icon[icon="users"]')).toBeAttached();
  const user = await page.evaluate(async () => (await fetch('/api/v1/admin/users')).json());
  expect(user.length).toBeGreaterThan(0);
  expect(user[0]).toHaveProperty('id');
  expect(user[0]).toHaveProperty('email');
  expect(user[0]).toHaveProperty('role');
  const self = user.find((entry) => entry.id.startsWith('test-'));
  expect(self).toBeDefined();
  expect(Date.parse(self.lastSeen)).toBeGreaterThan(Date.now() - 60_000);
  if (!self.preferredUsername) {
    const username = `admin_${Date.now()}`;
    const status = await page.evaluate(
      async ({ id, preferred_username }) => {
        const response = await fetch(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ preferred_username }),
        });
        return response.status;
      },
      { id: self.id, preferred_username: username },
    );
    expect(status).toBe(200);
    self.preferredUsername = username;
    await page.reload();
  }
  await page.getByRole('button', { name: self.email }).click();
  await expect(page.getByText('Name:').locator('..')).toContainText('John Doe');
  await expect(page.getByText(/Last authenticated:/)).toBeVisible();
  await expect(page.locator('input[name="preferred_username"]')).toHaveValue(self.preferredUsername || '');
  const response = await page.evaluate(async (id) => {
    const result = await fetch(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ disabled: true }),
    });
    return result.status;
  }, self.id);
  expect(response).toBe(409);
});

test('preferred username can be set once and cannot be changed through the API', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } });
  }, testKey);

  const profile = await page.evaluate(async () => (await fetch('/api/v1/profile')).json());
  let preferredUsername = profile.preferred_username;
  await page.goto('/me');
  await page.getByRole('button', { name: 'Profile' }).click();
  if (!preferredUsername) {
    await expect(page.locator('#v2-preferred-username')).toBeVisible();
    preferredUsername = `test_${Math.random().toString(36).slice(2, 10)}`;
    await page.locator('#v2-preferred-username').fill(preferredUsername);
    await page.getByRole('button', { name: 'Save username' }).click();
    await expect(page.locator('#v2-username-status')).toContainText('Username saved.');
    await expect(page.locator('#v2-preferred-username')).toHaveCount(0);
    await expect(page.getByText('Saved username:').locator('..')).toContainText(preferredUsername);
  } else {
    await expect(page.locator('#v2-preferred-username')).toHaveCount(0);
    await expect(page.getByText('Saved username:').locator('..')).toContainText(preferredUsername);
  }

  const changeResponse = await page.evaluate(async () =>
    fetch('/api/v1/profile/preferred-username', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ preferred_username: `changed_${Math.random().toString(36).slice(2, 10)}` }),
    }).then((response) => response.status),
  );
  expect(changeResponse).toBe(409);
  const updatedProfile = await page.evaluate(async () => (await fetch('/api/v1/profile')).json());
  expect(updatedProfile.preferred_username).toBe(preferredUsername);
});

test('native public OIDC clients register private-use redirects and authorize with S256 PKCE', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  test.skip(process.env.OIDC_INTEGRATION_ENABLED !== 'true', 'Requires a signing-enabled OIDC test instance');
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', { method: 'POST', headers: { 'x-test-secret': secret } });
  }, testKey);

  const clientId = `native_${Math.random().toString(36).slice(2, 10)}`;
  const redirectUri = 'com.example.auth:/oauth2redirect';
  const logoutRedirectUri = 'com.example.auth:/signed-out';
  const createResult = await page.evaluate(
    async ({ clientId, redirectUri, logoutRedirectUri }) =>
      fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id: clientId,
          redirectUris: [redirectUri],
          postLogoutRedirectUris: [logoutRedirectUri],
          scopes: ['profile', 'email'],
          isPublic: true,
        }),
      }).then(async (response) => ({ status: response.status, body: await response.text() })),
    { clientId, redirectUri, logoutRedirectUri },
  );
  expect(createResult.status, createResult.body).toBe(201);

  try {
    const { authorizationUrl, verifier } = await page.evaluate(
      async ({ clientId, redirectUri }) => {
        const verifier = crypto.randomUUID().replaceAll('-', '').padEnd(43, 'a');
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const url = new URL('/authorize', location.origin);
        url.search = new URLSearchParams({
          response_type: 'code',
          client_id: clientId,
          redirect_uri: redirectUri,
          state: 'native_state',
          scope: 'openid profile email offline_access',
          nonce: 'native_nonce',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
        return { authorizationUrl: String(url), verifier };
      },
      { clientId, redirectUri },
    );
    const authorization = await page.request.get(authorizationUrl, { maxRedirects: 0 });
    expect(authorization.status()).toBe(302);
    const callback = new URL(authorization.headers().location);
    expect(callback.protocol).toBe('com.example.auth:');
    expect(callback.searchParams.get('state')).toBe('native_state');
    const code = callback.searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResponse = await page.request.post('/token', {
      form: {
        grant_type: 'authorization_code',
        client_id: clientId,
        code: code!,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    expect(tokenResponse.status()).toBe(200);
    const tokens = await tokenResponse.json();
    expect(tokens.scope).toBe('openid profile email offline_access');
    expect(tokens.refresh_token).toBeTruthy();
    const idClaims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());
    expect(idClaims.sub).toBeTruthy();
    expect(idClaims.nonce).toBe('native_nonce');
    expect(idClaims.preferred_username).toBeTruthy();

    const userInfoResponse = await page.request.get('/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userInfoResponse.status()).toBe(200);
    const userInfo = await userInfoResponse.json();
    expect(userInfo.sub).toBe(idClaims.sub);
    expect(userInfo.preferred_username).toBe(idClaims.preferred_username);

    const refreshResponse = await page.request.post('/token', {
      form: {
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: tokens.refresh_token,
      },
    });
    expect(refreshResponse.status()).toBe(200);
    const refreshed = await refreshResponse.json();
    expect(refreshed.refresh_token).toBeTruthy();
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.scope).toBe('openid profile email offline_access');

    const replayResponse = await page.request.post('/token', {
      form: {
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: tokens.refresh_token,
      },
    });
    expect(replayResponse.status()).toBe(400);
    expect(await replayResponse.json()).toEqual({ error: 'invalid_grant' });
    const revokedFamilyResponse = await page.request.post('/token', {
      form: {
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: refreshed.refresh_token,
      },
    });
    expect(revokedFamilyResponse.status()).toBe(400);

    const logoutUrl = new URL('/logout', 'http://127.0.0.1:3100');
    logoutUrl.search = new URLSearchParams({
      client_id: clientId,
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: logoutRedirectUri,
      state: 'logout_state',
    });
    const logoutResponse = await page.request.get(String(logoutUrl), { maxRedirects: 0 });
    expect(logoutResponse.status()).toBe(302);
    const logoutCallback = new URL(logoutResponse.headers().location);
    expect(logoutCallback.href.startsWith(logoutRedirectUri)).toBe(true);
    expect(logoutCallback.searchParams.get('state')).toBe('logout_state');
    expect((await page.request.get('/api/v1/profile')).status()).toBe(401);
  } finally {
    await page.evaluate(async (id) => {
      await fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' });
    }, clientId);
  }
});

test('removed account route returns not found', async ({ request }) => {
  const response = await request.get('/account', { maxRedirects: 0 });
  expect(response.status()).toBe(404);
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
      fetch('/api/v1/oidc/clients').then((response) => response.status),
      fetch('/api/v1/api-tokens/apps').then((response) => response.status),
      fetch('/api/v1/api-tokens/example').then((response) => response.status),
    ]),
  );
  expect(responses).toEqual([200, 200, 200]);
});

test('test-only session can access the dashboard sections', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await allowLocalLi3Imports(page);
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
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await page.goto('/me#security');
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await page.goto('/me#properties');
  await expect(page.getByRole('heading', { name: 'Properties' })).toBeVisible();
  await page.goto('/me#activity');
  await expect(page.getByRole('heading', { name: 'Authentication history' })).toBeVisible();
  await page.goto('/me#oidc');
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
  await expect(page.getByText(/Confidential clients are server-side apps/)).toBeVisible();
});

test('v2 dashboard and profile page stay compact at mobile widths', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  await allowLocalLi3Imports(page);
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
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  const mobileContentGap = await page.evaluate(() => {
    const header = document.querySelector('main > header').getBoundingClientRect();
    const content = document.querySelector('main > div.bg-white').getBoundingClientRect();
    return content.top - header.bottom;
  });
  expect(mobileContentGap).toBe(16);

  await page.setViewportSize({ width: 360, height: 800 });
  const narrowPageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(narrowPageWidth).toBeLessThanOrEqual(360);
  await page.setViewportSize({ width: 390, height: 844 });

  await page.getByRole('button', { name: 'Open menu' }).click();
  await page.getByRole('button', { name: 'Profile' }).click();
  await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
  const layout = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
    profileSectionRight: document.querySelector('.content-section').getBoundingClientRect().right,
  }));

  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.profileSectionRight).toBeLessThanOrEqual(layout.viewportWidth);
});

test('profile page shows identity, copies OIDC subject, and signs out', async ({ page }) => {
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
  const removedAccount = await page.request.get('/account', { maxRedirects: 0 });
  expect(removedAccount.status()).toBe(404);
  await page.setViewportSize({ width: 360, height: 800 });
  await page.getByRole('button', { name: 'Open menu' }).click();
  await page.getByRole('button', { name: 'Profile' }).click();
  await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'John Doe' })).toBeVisible();
  await expect(page.locator('v2-profile').getByText(/john\.doe\+.*@example\.test/)).toBeVisible();
  await expect(page.locator('v2-profile').getByLabel('Administrator')).toBeVisible();
  const subject = await page.locator('#profile-subject').innerText();
  const profile = await page.evaluate(() => fetch('/api/v1/profile').then((response) => response.json()));
  expect(subject).toBe(profile.id);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
  await page.getByRole('button', { name: 'Copy OIDC subject' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'OIDC subject copied.' })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(subject);
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
    const appRow = page.getByRole('listitem').filter({ has: app });
    await expect(appRow.getByRole('heading', { name: 'Scopes' })).toBeVisible();
    await expect(appRow.getByRole('heading', { name: 'Tokens' })).toBeVisible();
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
      const app = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['profile'] }),
      });
      if (!app.ok) throw new Error(`Could not create test app: ${app.status}`);
      const token = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`, {
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
    if (new URL(request.url()).pathname === '/api/v1/oidc/clients' && request.method() === 'GET') appListRequests += 1;
  });
  await page.goto('/me#oidc');
  try {
    const app = page.locator('details').filter({ hasText: appId });
    await app.locator('summary').click();
    const appRow = page.getByRole('listitem').filter({ hasText: appId });
    await expect(appRow.getByText('existing test token')).toBeVisible();
    expect(appListRequests).toBe(1);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
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
  const appForm = page.locator('v2-app-form');
  await appForm.getByPlaceholder('App ID').fill(appId);
  await appForm.getByPlaceholder('https://app.example/callback').fill(`https://${appId}.example/callback`);
  await appForm.getByRole('button', { name: 'Add', exact: true }).first().click();
  await appForm.getByPlaceholder('new:scope').fill('read:profile');
  await appForm.getByRole('button', { name: 'Add', exact: true }).last().click();
  await appForm.getByRole('button', { name: 'Create app' }).click();

  try {
    const app = page.locator('details').filter({ hasText: appId });
    await app.locator('summary').click();
    const appRow = page.getByRole('listitem').filter({ hasText: appId });
    await appRow.getByPlaceholder('Token label').fill('e2e token');
    await appRow.getByLabel('read:profile').check();
    await appRow.getByRole('button', { name: 'Generate token' }).click();
    const generatedTokenBox = appRow.locator('v2-copy-value-box');
    await expect(generatedTokenBox).toBeVisible();
    expect(await generatedTokenBox.getByRole('textbox', { name: 'Value to copy' }).inputValue()).toMatch(/^auth_/);
    await expect(appRow.getByText('e2e token')).toBeVisible();

    await page.reload();
    const reloadedApp = page.locator('details').filter({ hasText: appId });
    await reloadedApp.locator('summary').click();
    const reloadedAppRow = page.getByRole('listitem').filter({ hasText: appId });
    await expect(reloadedAppRow.getByText('e2e token')).toBeVisible();

    page.once('dialog', (dialog) => dialog.accept());
    await reloadedAppRow.getByRole('button', { name: 'Revoke' }).click();
    await expect(reloadedAppRow.getByText(/^Revoked /)).toBeVisible();
    await expect(reloadedAppRow.getByText('Active')).toHaveCount(0);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
});

test('Auth API token selector loads clients and supports create, scope expansion, and revoke', async ({
  page,
  request,
}) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appId = `e2e-auth-api-${Date.now()}`;
  const otherAppId = `${appId}-other`;
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
    const response = await fetch('/api/v1/oidc/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['storage:limits'] }),
    });
    if (!response.ok) throw new Error(`Could not create test app: ${response.status}`);
  }, appId);

  try {
    const otherCreated = await page.evaluate(async (id) => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['other:scope'] }),
      });
      return response.status;
    }, otherAppId);
    expect(otherCreated).toBe(201);

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
    await expect(page.getByText('Copy this Auth API token now. It is only shown once.')).toBeVisible();
    await expect(page.getByText('browser test token')).toBeVisible();
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    const copyBox = page.locator('v2-copy-value-box').last();
    const tokenInput = copyBox.getByRole('textbox', { name: 'Value to copy' });
    const managementToken = await tokenInput.inputValue();
    expect(managementToken).toMatch(/^auth_/);
    await tokenInput.click();
    expect(
      await tokenInput.evaluate(
        (input: HTMLInputElement) => input.selectionStart === 0 && input.selectionEnd === input.value.length,
      ),
    ).toBeTruthy();
    await copyBox.getByRole('button', { name: 'Copy' }).click();
    await expect(copyBox.getByText('Copied to clipboard.')).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(managementToken);
    await expect(copyBox.getByText('Copied to clipboard.')).toBeHidden({ timeout: 7000 });
    await selector.selectOption('');
    await expect(page.getByText('browser test token')).toBeVisible();
    await selector.selectOption(appId);
    const issued = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/issue`, {
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
    const notYetAllowed = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/issue`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ label: 'new scope before configuration', scopes: ['storage:catalog:read'] }),
        });
        return response.status;
      },
      { id: appId, token: managementToken! },
    );
    expect(notYetAllowed).toBe(400);

    const scopeAddition = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/scopes`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ scopes: ['storage:catalog:read', 'storage:catalog:read'] }),
        });
        return { status: response.status, body: await response.json() };
      },
      { id: appId, token: managementToken! },
    );
    expect(scopeAddition.status).toBe(200);
    expect(scopeAddition.body.scopes).toEqual(['storage:limits', 'storage:catalog:read']);

    const issueNewScope = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/issue`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ label: 'newly configured scope', scopes: ['storage:catalog:read'] }),
        });
        return response.status;
      },
      { id: appId, token: managementToken! },
    );
    expect(issueNewScope).toBe(201);

    const wrongClient = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/scopes`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ scopes: ['attacker:scope'] }),
        });
        return response.status;
      },
      { id: otherAppId, token: managementToken! },
    );
    expect(wrongClient).toBe(401);

    const cannotRemove = await request.put(`/api/v1/oidc/clients/${encodeURIComponent(appId)}/scopes`, {
      headers: { authorization: `Bearer ${managementToken}` },
      data: { scopes: ['storage:catalog:read'] },
    });
    expect(cannotRemove.status()).toBe(403);

    const malformedScopes = await page.evaluate(
      async ({ id, token }) => {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}/scopes`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ scopes: ['invalid scope'] }),
        });
        return response.status;
      },
      { id: appId, token: managementToken! },
    );
    expect(malformedScopes).toBe(400);

    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Revoke' }).click();
    await expect(page.getByText('revoked', { exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      otherAppId,
    );
  }
});

test('OIDC client deletion without admin access returns 403', async ({ request }) => {
  const response = await request.delete('/api/v1/oidc/clients/some-client-id');
  expect(response.status()).toBe(403);
});

test('OIDC client secret regeneration without admin access returns 403', async ({ request }) => {
  const response = await request.put('/api/v1/oidc/clients/some-client-id/secret', {
    json: {},
  });
  expect(response.status()).toBe(403);
});

test('registered OIDC clients can revoke opaque API tokens', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const appId = `e2e-revoke-${Date.now()}`;
  await page.goto('/');
  await page.evaluate(async (secret) => {
    await fetch('/__test__/login', {
      method: 'POST',
      headers: { 'x-test-secret': secret, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
  }, testKey);

  const setup = await page.evaluate(async (id) => {
    const appResponse = await fetch('/api/v1/oidc/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id, redirectUris: [`https://${id}.example/callback`], scopes: ['profile'] }),
    });
    if (!appResponse.ok) throw new Error('Could not create test OIDC client');
    const app = await appResponse.json();
    const tokenResponse = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ label: 'revoke test token', scopes: ['profile'] }),
    });
    if (!tokenResponse.ok) throw new Error('Could not create test API token');
    const token = await tokenResponse.json();
    return { secret: app.secret, token: token.token };
  }, appId);

  try {
    const result = await page.evaluate(
      async ({ id, secret, token }) => {
        const credentials = btoa(`${id}:${secret}`);
        const headers = {
          authorization: `Basic ${credentials}`,
          'content-type': 'application/x-www-form-urlencoded',
        };
        const revoked = await fetch('/api/v1/revoke', {
          method: 'POST',
          headers,
          body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
        });
        const introspected = await fetch('/oauth/introspect', {
          method: 'POST',
          headers,
          body: new URLSearchParams({ token }),
        });
        return { revokeStatus: revoked.status, active: (await introspected.json()).active };
      },
      { id: appId, ...setup },
    );
    expect(result.revokeStatus).toBe(200);
    expect(result.active).toBe(false);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
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
      const response = await fetch('/api/v1/oidc/clients', {
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
      const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`, {
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
    const card = page.getByRole('listitem').filter({ hasText: appId });

    const secretResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/api/v1/oidc/clients/${appId}/secret` && response.request().method() === 'PUT';
    });
    page.once('dialog', (dialog) => dialog.accept());
    await card.getByRole('button', { name: 'Regenerate secret' }).click();
    const secretResponse = await secretResponsePromise;
    expect(secretResponse.status()).toBe(200);
    const regenerated = await secretResponse.json();
    expect(regenerated.secret).toBeTruthy();
    expect(regenerated.secret).not.toBe(created.secret);
    const secretBox = card.locator('v2-copy-value-box');
    await expect(secretBox).toBeVisible();
    await expect(secretBox.getByRole('textbox', { name: 'Value to copy' })).toHaveValue(regenerated.secret);

    const deleteResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/api/v1/oidc/clients/${appId}` && response.request().method() === 'DELETE';
    });
    page.once('dialog', (dialog) => dialog.accept());
    await card.getByRole('button', { name: 'Delete application' }).click();
    const deleteResponse = await deleteResponsePromise;
    expect(deleteResponse.status()).toBe(204);
    await expect(card).toHaveCount(0);
    const remainingTokens = await page.evaluate(async (id) => {
      const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`);
      return response.json();
    }, appId);
    expect(remainingTokens).toEqual([]);
  } finally {
    await page.evaluate(
      async (id) => fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
      appId,
    );
  }
});
