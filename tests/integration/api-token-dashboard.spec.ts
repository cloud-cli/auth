import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent } from './agent-fixture.js';

test('Tokens lists downstream tokens across apps and filters by app', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    const clients = await page.evaluate(async () => {
      const result = [];
      for (const name of ['Token dashboard A', 'Token dashboard B']) {
        const response = await fetch('/api/v1/oidc/clients', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            name,
            redirectUris: [`https://${name.toLowerCase().replaceAll(' ', '-')}.example/callback`],
            scopes: ['dashboard:read'],
          }),
        });
        if (!response.ok) throw new Error('Could not create app for token dashboard test');
        result.push(await response.json());
      }
      for (let index = 0; index < result.length; index += 1) {
        const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(result[index].id)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ label: `Dashboard token ${index + 1}`, scopes: ['dashboard:read'] }),
        });
        if (!response.ok) throw new Error('Could not create API token for dashboard test');
      }
      return result;
    });

    await page.goto('/me#tokens');
    await expect(page.getByRole('heading', { name: 'Tokens' })).toBeVisible();
    await expect(page.getByText('Dashboard token 1', { exact: true })).toBeVisible();
    await expect(page.getByText('Dashboard token 2', { exact: true })).toBeVisible();
    await expect(page.getByText(`Token dashboard A · ${clients[0].id}`, { exact: true })).toBeVisible();
    await expect(page.getByText(`Token dashboard B · ${clients[1].id}`, { exact: true })).toBeVisible();

    await page.getByLabel('Filter by app').selectOption(clients[0].id);
    await expect(page.getByText('Dashboard token 1', { exact: true })).toBeVisible();
    await expect(page.getByText('Dashboard token 2', { exact: true })).toHaveCount(0);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('an OIDC client can revoke one of its owner-issued downstream tokens', async ({ page }) => {
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
          name: 'Downstream revocation app',
          redirectUris: ['https://downstream-revoke.example/callback'],
          scopes: ['downstream:read'],
        }),
      });
      if (!response.ok) throw new Error(`Could not create OIDC app (${response.status}).`);
      return response.json();
    });
    const token = await page.evaluate(async (clientId) => {
      const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'Revocation test token', scopes: ['downstream:read'] }),
      });
      if (!response.ok) throw new Error(`Could not create downstream token (${response.status}).`);
      return response.json();
    }, app.id);

    const result = await page.evaluate(
      async ({ clientId, secret, presentedToken }) => {
        const headers = {
          authorization: `Basic ${btoa(`${clientId}:${secret}`)}`,
          'content-type': 'application/x-www-form-urlencoded',
        };
        const revoked = await fetch('/api/v1/revoke', {
          method: 'POST',
          headers,
          body: new URLSearchParams({ token: presentedToken, token_type_hint: 'access_token' }),
        });
        const introspected = await fetch('/oauth/introspect', {
          method: 'POST',
          headers,
          body: new URLSearchParams({ token: presentedToken }),
        });
        return { revokeStatus: revoked.status, active: (await introspected.json()).active };
      },
      { clientId: app.id, secret: app.secret, presentedToken: token.token },
    );
    expect(result).toEqual({ revokeStatus: 200, active: false });
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});
