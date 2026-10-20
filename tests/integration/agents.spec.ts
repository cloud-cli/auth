import { createHash, randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import {
  createAdminFixture,
  createAgentFixture,
  deleteAdminFixture,
  deleteAgentFixture,
  signInAsAgent,
  type AdminFixture,
  type AgentFixture,
} from './agent-fixture.js';

test('Agents sign in as distinct accounts and cannot use human or admin security APIs', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    const profile = await page.evaluate(async () => {
      const response = await fetch('/api/v1/profile');
      return response.json();
    });
    expect(profile.role).toBe('agent');
    expect(profile.id).toBe(fixture.agentId);

    for (const section of ['Profile', 'Properties', 'Applications', 'Agents', 'Tokens']) {
      await expect(page.getByRole('button', { name: section })).toBeVisible();
    }
    for (const section of ['Security', 'Activity', 'Users']) {
      await expect(page.getByRole('button', { name: section })).toHaveCount(0);
    }

    const protectedStatuses = await page.evaluate(async () => {
      const requests = [
        fetch('/api/v1/keys'),
        fetch('/api/v1/audit'),
        fetch('/api/v1/webauthn/credentials'),
        fetch('/api/v1/recovery-codes', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        }),
        fetch('/api/v1/auth-api-tokens/unknown'),
      ];
      return Promise.all(requests.map(async (request) => (await request).status));
    });
    expect(protectedStatuses).toEqual([403, 403, 403, 403, 403]);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('Applications creates a private app with a generated ID and no downstream-token controls', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    await page.goto('/me#applications');
    await page.getByRole('button', { name: 'Add app' }).click();
    const form = page.locator('v2-app-form');
    await form.getByPlaceholder('Application name').fill('Agent UI application');
    await form.getByPlaceholder('https://app.example/callback').fill('https://agent-ui.example/callback');
    await form.getByRole('button', { name: 'Add', exact: true }).nth(0).click();
    await form.getByPlaceholder('new:scope').fill('agent-ui:read');
    await form.getByRole('button', { name: 'Add', exact: true }).nth(2).click();
    await expect(form.getByPlaceholder('Application ID')).toHaveCount(0);
    await form.getByRole('button', { name: 'Create app' }).click();
    await expect(page.getByText('Copy this new client secret now. It is only shown once.')).toBeVisible();
    const secretField = form.getByRole('button', { name: 'Copy full value to clipboard' });
    await expect(secretField).toContainText(/…\s*[A-Za-z0-9_-]{3}$/);
    await secretField.click();
    const initialSecret = await page.evaluate(() => navigator.clipboard.readText());
    expect(initialSecret).toMatch(/^[A-Za-z0-9_-]+$/);

    const apps = await page.evaluate(async () => (await fetch('/api/v1/oidc/apps')).json());
    const app = apps.find((item) => item.name === 'Agent UI application');
    expect(app).toMatchObject({ availableToUsers: false, canManage: true, scopes: ['agent-ui:read'] });
    expect(app.id).toMatch(/^app_[A-Za-z0-9_-]+$/);

    const details = page.locator('details').filter({ hasText: app.id });
    await details.locator('summary').click();
    const row = page.getByRole('listitem').filter({ hasText: app.id });
    await expect(row.getByText('https://agent-ui.example/callback', { exact: true })).toBeVisible();
    await expect(row.getByText('agent-ui:read', { exact: true })).toBeVisible();
    await row.getByLabel('Application name').fill('Renamed Agent UI application');
    await row.getByRole('button', { name: 'Save name' }).click();
    await expect(row.getByText('Renamed Agent UI application', { exact: true })).toBeVisible();
    await expect(row.getByPlaceholder('Token label')).toHaveCount(0);
    await expect(row.getByRole('button', { name: 'Generate token' })).toHaveCount(0);

    const secretResponsePromise = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === `/api/v1/oidc/clients/${app.id}/secret` &&
        response.request().method() === 'PUT',
    );
    page.once('dialog', (dialog) => dialog.accept());
    await row.getByRole('button', { name: 'Regenerate secret' }).click();
    const secretResponse = await secretResponsePromise;
    expect(secretResponse.status()).toBe(200);
    const regenerated = await secretResponse.json();
    expect(regenerated.secret).toBeTruthy();
    expect(regenerated.secret).not.toBe(initialSecret);
    const regeneratedField = row.getByRole('button', { name: 'Copy full value to clipboard' });
    await expect(regeneratedField).toContainText(new RegExp(`…\\s*${regenerated.secret.slice(-3)}`));
    await regeneratedField.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(regenerated.secret);

    const deleteResponsePromise = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === `/api/v1/oidc/clients/${app.id}` &&
        response.request().method() === 'DELETE',
    );
    page.once('dialog', (dialog) => dialog.accept());
    await row.getByRole('button', { name: 'Delete application' }).click();
    expect((await deleteResponsePromise).status()).toBe(204);
    await expect(row).toHaveCount(0);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('Agent creation shows the Agent ID and sign-in token as copyable values', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    await page.goto('/me#agents');
    await page.getByPlaceholder('Agent name').fill('Copy UI child');
    await page.getByRole('button', { name: 'Create Agent' }).click();

    const valueBoxes = page.locator('v2-copy-value-box');
    await expect(valueBoxes).toHaveCount(2);
    const copyFields = page.getByRole('button', { name: 'Copy full value to clipboard' });
    await expect(copyFields).toHaveCount(2);
    await expect(valueBoxes.nth(1)).toContainText('Agent ID');

    await copyFields.nth(1).click();
    const agentId = await page.evaluate(() => navigator.clipboard.readText());
    expect(agentId).toMatch(/^agent_[A-Za-z0-9_-]+$/);
    const childRow = page.getByRole('listitem').filter({ hasText: 'Copy UI child' });
    await expect(childRow.locator('code')).toHaveText(agentId);

    await copyFields.nth(0).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^agt_[A-Za-z0-9_-]+$/);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('Agents own private OIDC apps and manage scoped downstream tokens from Tokens', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    const created = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id: 'caller-selected-client-id',
          name: 'Agent E2E app',
          redirectUris: ['https://agent-e2e.example/callback'],
          scopes: ['agent:read', 'agent:write'],
        }),
      });
      return { status: response.status, body: await response.json() };
    });
    expect(created.status).toBe(201);
    expect(created.body.id).toMatch(/^app_[A-Za-z0-9_-]+$/);
    expect(created.body.id).not.toBe('Agent E2E app');
    expect(created.body.id).not.toBe('caller-selected-client-id');

    const updatedName = await page.evaluate(async (clientId) => {
      const response = await fetch(`/api/v1/oidc/clients/${encodeURIComponent(clientId)}/name`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Renamed Agent E2E app' }),
      });
      return { status: response.status, body: await response.json() };
    }, created.body.id);
    expect(updatedName).toEqual({ status: 200, body: { name: 'Renamed Agent E2E app' } });

    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const authorization = new URLSearchParams({
      response_type: 'code',
      client_id: created.body.id,
      redirect_uri: 'https://agent-e2e.example/callback',
      state: 'agent-private-app-state',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      scope: 'openid',
    });
    const authorizationResponse = await page.request.get(`/authorize?${authorization}`, { maxRedirects: 0 });
    expect(authorizationResponse.status()).toBe(302);
    const callback = new URL(authorizationResponse.headers().location);
    expect(callback.searchParams.get('code')).toBeTruthy();
    expect(callback.searchParams.get('state')).toBe('agent-private-app-state');

    const apps = await page.evaluate(async () => (await fetch('/api/v1/oidc/apps')).json());
    const app = apps.find((item) => item.id === created.body.id);
    expect(app).toMatchObject({ name: 'Renamed Agent E2E app', availableToUsers: false, canManage: true });

    await page.goto('/me#tokens');
    await expect(page.getByRole('heading', { name: 'Tokens' })).toBeVisible();
    await page.getByRole('button', { name: 'Create token' }).click();
    const createButton = page.getByRole('button', { name: 'Create', exact: true });
    await expect(createButton).toBeDisabled();
    await page.getByLabel('OIDC application').selectOption(created.body.id);
    await expect(page.getByLabel('agent:read')).toBeVisible();
    await page.getByLabel('agent:read').check();
    await createButton.click();
    const createdTokenField = page.getByRole('button', { name: 'Copy full value to clipboard' });
    await expect(createdTokenField).toContainText(/…\s*[A-Za-z0-9_-]{3}$/);
    await createdTokenField.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^auth_/);

    const appFilter = page.getByLabel('Filter by app');
    await appFilter.selectOption(created.body.id);
    await expect(page.getByText('Renamed Agent E2E app · ' + created.body.id)).toBeVisible();
    await expect(page.getByText('Scopes: agent:read')).toBeVisible();

    await page.getByRole('button', { name: 'Edit scopes' }).click();
    await page.getByLabel('agent:write').check();
    await page.getByRole('button', { name: 'Save scopes' }).click();
    await expect(page.getByText('Scopes: agent:read, agent:write')).toBeVisible();

    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Rotate' }).click();
    const rotatedTokenField = page.getByRole('button', { name: 'Copy full value to clipboard' });
    await expect(rotatedTokenField).toContainText(/…\s*[A-Za-z0-9_-]{3}$/);
    await rotatedTokenField.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^auth_/);
    await expect(page.getByText('Revoked', { exact: false })).toBeVisible();
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Revoke' }).click();
    await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('private apps stay owner-scoped until an administrator publishes them', async ({ browser, page }) => {
  const owner = await createAgentFixture(page);
  if (!owner) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }
  const administratorPage = await browser.newPage();
  const consumerPage = await browser.newPage();
  let administrator: AdminFixture | null = null;
  let consumer: AgentFixture | null = null;

  try {
    await signInAsAgent(page, owner);
    const created = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'Private publication test',
          redirectUris: ['https://publication.example/callback'],
        }),
      });
      return { status: response.status, body: await response.json() };
    });
    expect(created.status).toBe(201);

    consumer = await createAgentFixture(consumerPage);
    if (!consumer) throw new Error('Could not create consumer Agent fixture.');
    await signInAsAgent(consumerPage, consumer);
    let visibility = await consumerPage.evaluate(async (clientId) => {
      const [apps, tokens] = await Promise.all([
        fetch('/api/v1/oidc/apps').then((response) => response.json()),
        fetch(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`).then((response) => response.status),
      ]);
      return { app: apps.find((item) => item.id === clientId), tokenStatus: tokens };
    }, created.body.id);
    expect(visibility).toEqual({ app: undefined, tokenStatus: 404 });

    administrator = await createAdminFixture(administratorPage);
    if (!administrator) throw new Error('Could not create administrator fixture.');
    const adminCreatedApp = await administratorPage.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Private admin app', redirectUris: ['https://admin-private.example/callback'] }),
      });
      return { status: response.status, body: await response.json() };
    });
    expect(adminCreatedApp.status).toBe(201);
    const globalApps = await administratorPage.evaluate(async () => (await fetch('/api/v1/oidc/apps')).json());
    expect(globalApps.find((app) => app.id === created.body.id)).toMatchObject({
      canManage: true,
      availableToUsers: false,
    });
    expect(globalApps.find((app) => app.id === adminCreatedApp.body.id)).toMatchObject({
      canManage: true,
      availableToUsers: false,
    });
    const publishStatus = await administratorPage.evaluate(async (clientId) => {
      const response = await fetch(`/api/v1/oidc/clients/${encodeURIComponent(clientId)}/availability`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ availableToUsers: true }),
      });
      return response.status;
    }, created.body.id);
    expect(publishStatus).toBe(200);

    visibility = await consumerPage.evaluate(async (clientId) => {
      const [apps, tokenResponse] = await Promise.all([
        fetch('/api/v1/oidc/apps').then((response) => response.json()),
        fetch(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`),
      ]);
      return { app: apps.find((item) => item.id === clientId), tokenStatus: tokenResponse.status };
    }, created.body.id);
    expect(visibility.app).toMatchObject({
      name: 'Private publication test',
      canManage: false,
      availableToUsers: true,
    });
    expect(visibility.tokenStatus).toBe(200);

    const nonOwnerEditStatus = await consumerPage.evaluate(async (clientId) => {
      const response = await fetch(`/api/v1/oidc/clients/${encodeURIComponent(clientId)}/name`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Changed by consumer' }),
      });
      return response.status;
    }, created.body.id);
    expect(nonOwnerEditStatus).toBe(404);

    const unpublishStatus = await administratorPage.evaluate(async (clientId) => {
      const response = await fetch(`/api/v1/oidc/clients/${encodeURIComponent(clientId)}/availability`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ availableToUsers: false }),
      });
      return response.status;
    }, created.body.id);
    expect(unpublishStatus).toBe(200);
    const hiddenAgain = await consumerPage.evaluate(
      async (clientId) =>
        (await fetch('/api/v1/oidc/apps').then((response) => response.json())).some((app) => app.id === clientId),
      created.body.id,
    );
    expect(hiddenAgain).toBe(false);
  } finally {
    if (administrator) await deleteAdminFixture(administratorPage, administrator);
    if (consumer) await deleteAgentFixture(consumerPage, consumer);
    await deleteAgentFixture(page, owner);
    await administratorPage.close();
    await consumerPage.close();
  }
});
