import { expect, test } from '@playwright/test';
import {
  allowLocalLi3Imports,
  createAdminFixture,
  createAgentFixture,
  deleteAdminFixture,
  deleteAgentFixture,
  signInAsAgent,
} from './agent-fixture.js';

test('landing page and login are available', async ({ page }) => {
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

  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'A single auth for every app.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.locator('body')).toHaveAttribute('data-page', 'login');
  await expect(page.getByRole('link', { name: 'Continue with Google' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Use a passkey' })).toBeVisible();
  await expect(page.getByText('Try another way', { exact: true })).toBeVisible();
  await page.getByText('Try another way', { exact: true }).click();
  await expect(page.getByText('Sign in as an Agent', { exact: true })).toBeVisible();
  await page.getByText('Sign in as an Agent', { exact: true }).click();
  await expect(page.getByLabel('Agent ID')).toBeVisible();
  await expect(page.getByLabel('Sign-in token')).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(16, 23, 19)');
  await expect(page.getByTestId('login-card')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
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
  const passkey = page.getByRole('link', { name: 'Use a passkey' }).first();
  await page.keyboard.press('Tab');
  await expect(passkey).toBeFocused();
  await expect(passkey).toHaveCSS('color', 'rgb(255, 255, 255)');
  await expect(passkey).toHaveCSS('background-color', 'rgb(55, 109, 70)');

  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(passkey).toHaveCSS('color', 'rgb(255, 255, 255)');
  await expect(passkey).toHaveCSS('background-color', 'rgb(55, 109, 70)');
  await expect(passkey).toHaveCSS('outline-color', 'rgb(200, 230, 168)');
});

test('dashboard assets expose Agent and separate token components', async ({ request }) => {
  const legacyRoute = await request.get('/v2');
  expect(legacyRoute.status()).toBe(404);

  const pageResponse = await request.get('/ui/v2.html');
  expect(pageResponse.ok()).toBeTruthy();
  const page = await pageResponse.text();
  expect(page).toContain('<v2-layout class="block h-full w-full"></v2-layout>');
  expect(page).toContain('dashboard-agents.html');
  expect(page).toContain('dashboard-api-tokens.html');
  expect(page).not.toContain('Management /');

  for (const asset of [
    'dashboard-layout.html',
    'dashboard-security.html',
    'dashboard-properties.html',
    'dashboard-applications.html',
    'dashboard-app-editor.html',
    'dashboard-app-form.html',
    'dashboard-agents.html',
    'dashboard-api-tokens.html',
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

test('session-dependent app entry is not cached or conditionally revalidated', async ({ request }) => {
  const response = await request.get('/me', { headers: { 'if-none-match': '*' } });
  expect(response.status()).toBe(200);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers().vary).toContain('Cookie');
});

test('Agent sessions survive duplicate stale cookies and expose only Agent dashboard navigation', async ({
  page,
  context,
}) => {
  await allowLocalLi3Imports(page);
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
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
    await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
    for (const section of ['Profile', 'Properties', 'Applications', 'Agents', 'Tokens']) {
      await expect(page.getByRole('button', { name: section })).toBeVisible();
    }
    await expect(page.getByRole('button', { name: 'Security' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Activity' })).toHaveCount(0);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('public modules, OpenAPI, and OIDC discovery are served', async ({ request }) => {
  for (const path of [
    '/index.mjs',
    '/node.mjs',
    '/ui/dashboard.mjs',
    '/ui/lib.mjs',
    '/ui/lucide-icon.html',
    '/ui/icons/v1.59.0/menu.svg',
    '/ui/embed.html',
  ]) {
    const response = await request.get(path);
    expect(response.ok(), path).toBeTruthy();
  }
  const menuIcon = await request.get('/ui/icons/v1.59.0/menu.svg');
  expect(menuIcon.headers()['content-type']).toContain('image/svg+xml');
  expect(menuIcon.headers()['cache-control']).toContain('immutable');

  const response = await request.get('/api');
  expect(response.ok()).toBeTruthy();
  const spec = await response.json();
  expect(spec.openapi).toBe('3.1.0');
  expect(spec.paths['/authorize']).toBeDefined();
  expect(spec.paths['/oauth/introspect']).toBeDefined();
  expect(spec.paths['/index.mjs']).toBeDefined();
  expect(spec.paths['/node.mjs']).toBeDefined();
  expect(spec.paths['/api/v1/profile']).toBeDefined();
  expect(spec.paths['/api/v1/agents']).toBeDefined();
  expect(spec.paths['/api/v1/oidc/apps']).toBeDefined();
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

test('profile API stays protected and admin-only page errors are branded', async ({ request }) => {
  const profile = await request.get('/api/v1/profile');
  expect(profile.status()).toBe(401);

  const response = await request.get('/oidc', { headers: { accept: 'text/html' } });
  expect(response.status()).toBe(403);
  const body = await response.text();
  expect(body).toContain('Welcome back');
  expect(body).toContain('Sign in with an administrator account to continue.');
  expect(body).not.toContain('{"error"');
});

test('administrator Users page lists accounts and prevents disabling its active administrator', async ({ page }) => {
  await allowLocalLi3Imports(page);
  const agentFixture = await createAgentFixture(page);
  if (!agentFixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  const fixture = await createAdminFixture(page);
  if (!fixture) {
    await deleteAgentFixture(page, agentFixture);
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await page.goto('/me#users');
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
    const users = await page.evaluate(async () => (await fetch('/api/v1/admin/users')).json());
    const currentUser = users.find((user) => user.id === fixture.userId);
    expect(currentUser).toMatchObject({ role: 'admin', name: 'Integration Test Administrator' });
    expect(users.some((user) => user.role === 'agent')).toBe(false);
    expect(users.some((user) => user.id === agentFixture.agentId)).toBe(false);
    await expect(page.getByText(agentFixture.agentId, { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: currentUser.email }).click();
    await expect(page.getByText('UUID:', { exact: true })).toBeVisible();
    await expect(page.locator('input[name="preferred_username"]')).toBeVisible();

    const disableStatus = await page.evaluate(async (userId) => {
      const response = await fetch(`/api/v1/admin/users/${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ disabled: true }),
      });
      return response.status;
    }, fixture.userId);
    expect(disableStatus).toBe(409);
  } finally {
    await deleteAdminFixture(page, fixture);
    await deleteAgentFixture(page, agentFixture);
  }
});

test('an Agent can set a preferred username once and copy its independent OIDC subject', async ({ page }) => {
  await allowLocalLi3Imports(page);
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  try {
    await signInAsAgent(page, fixture);
    await page.goto('/me#profile');
    await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
    await expect(page.getByText('Agent', { exact: true })).toBeVisible();
    const username = `agent_${Math.random().toString(36).slice(2, 10)}`;
    await page.locator('#v2-preferred-username').fill(username);
    await page.getByRole('button', { name: 'Save username' }).click();
    await expect(page.locator('#v2-username-status')).toContainText('Username saved.');
    await expect(page.getByText('Saved username:').locator('..')).toContainText(username);

    const updateStatus = await page.evaluate(async () =>
      fetch('/api/v1/profile/preferred-username', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ preferred_username: 'a_different_name' }),
      }).then((response) => response.status),
    );
    expect(updateStatus).toBe(409);

    const subject = await page.locator('#profile-subject').innerText();
    const profile = await page.evaluate(async () => (await fetch('/api/v1/profile')).json());
    expect(subject).toBe(fixture.agentId);
    expect(profile.preferred_username).toBe(username);
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    await page.getByRole('button', { name: 'Copy OIDC subject' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'OIDC subject copied.' })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(subject);

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login$/);
    expect(pageErrors).toEqual([]);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('removed account route and unauthenticated OIDC management routes remain unavailable', async ({ request }) => {
  const removedAccount = await request.get('/account', { maxRedirects: 0 });
  expect(removedAccount.status()).toBe(404);
  expect((await request.get('/api/v1/oidc/clients')).status()).toBe(403);
  expect((await request.delete('/api/v1/oidc/clients/some-client-id')).status()).toBe(401);
  expect((await request.put('/api/v1/oidc/clients/some-client-id/secret', { data: {} })).status()).toBe(401);
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

test('invalid authorization requests return an actionable OAuth error to a registered Agent app', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    const app = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'Authorization error test',
          redirectUris: ['https://auth-error.example/callback'],
        }),
      });
      return response.json();
    });
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: app.id,
      redirect_uri: 'https://auth-error.example/callback',
      state: 'retry-state',
      code_challenge: 'invalid',
      code_challenge_method: 'S256',
      scope: 'openid',
    });
    const response = await page.request.get(`/authorize?${query}`, { maxRedirects: 0 });
    expect(response.status()).toBe(302);
    const callback = new URL(response.headers().location);
    expect(callback.origin + callback.pathname).toBe('https://auth-error.example/callback');
    expect(callback.searchParams.get('error')).toBe('invalid_request');
    expect(callback.searchParams.get('state')).toBe('retry-state');
    expect(callback.searchParams.get('error_description')).toContain('Start a new sign-in');
  } finally {
    await deleteAgentFixture(page, fixture);
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
