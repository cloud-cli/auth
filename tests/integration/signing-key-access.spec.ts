import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent } from './agent-fixture.js';

test('Agents cannot list or rotate server-wide signing keys', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    const statuses = await page.evaluate(async () => {
      const list = await fetch('/api/v1/keys');
      const rotate = await fetch('/api/v1/keys/rotate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      return [list.status, rotate.status];
    });
    expect(statuses).toEqual([403, 403]);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});
