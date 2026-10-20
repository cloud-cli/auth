import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent } from './agent-fixture.js';

test('Tokens scope editor opens and saves a valid scope selection', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);

    const createdApp = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: `E2E scope editor ${Date.now()}`,
          redirectUris: ['https://scope-editor.example/callback'],
          scopes: ['workflows:read', 'artifacts:read'],
        }),
      });
      return { status: response.status, body: await response.json() };
    });
    expect(createdApp.status).toBe(201);
    const appId = createdApp.body.id;

    const tokenStatus = await page.evaluate(async (id) => {
      const response = await fetch(`/api/v1/api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'scope editor test', scopes: ['workflows:read', 'artifacts:read'] }),
      });
      return response.status;
    }, appId);
    expect(tokenStatus).toBe(201);

    await page.goto('/me#tokens');
    await page.getByLabel('Filter by app').selectOption(appId);
    const tokenCard = page.locator('article').filter({ hasText: 'scope editor test' });
    await tokenCard.getByRole('button', { name: 'Edit scopes' }).click();
    await tokenCard.getByLabel('artifacts:read').uncheck();
    await tokenCard.getByRole('button', { name: 'Save scopes' }).click();
    await expect(tokenCard.getByText('Scopes: workflows:read', { exact: true })).toBeVisible();
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});
