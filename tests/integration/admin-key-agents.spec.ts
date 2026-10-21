import { expect, test } from '@playwright/test';
import { createAdminFixture, createAgentFixture, deleteAdminFixture, deleteAgentFixture } from './agent-fixture.js';

test('Admin keys create and manage Agents only in their OIDC client owner tree', async ({ page }) => {
  const administrator = await createAdminFixture(page);
  if (!administrator) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }
  let clientId = '';
  let createdAgentId = '';
  let adminKey = '';
  let foreignAgent: Awaited<ReturnType<typeof createAgentFixture>> = null;
  const cleanupErrors: unknown[] = [];

  try {
    const client = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'Admin key Agent API test',
          redirectUris: ['https://admin-key.example/callback'],
        }),
      });
      return { status: response.status, body: await response.json() };
    });
    expect(client.status).toBe(201);
    clientId = client.body.id;

    const key = await page.evaluate(async (id) => {
      const response = await fetch(`/api/v1/auth-api-tokens/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'Agent automation' }),
      });
      return { status: response.status, body: await response.json() };
    }, clientId);
    expect(key.status).toBe(201);
    adminKey = key.body.token;

    const agent = await page.evaluate(async (token) => {
      const response = await fetch('/api/v1/agents', {
        method: 'POST',
        credentials: 'omit',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Admin key created Agent' }),
      });
      return { status: response.status, body: await response.json() };
    }, adminKey);
    expect(agent.status).toBe(201);
    createdAgentId = agent.body.agent.id;
    expect(agent.body.token).toMatch(/^agt_/);

    const managedAgents = await page.evaluate(async (token) => {
      const response = await fetch('/api/v1/agents', {
        credentials: 'omit',
        headers: { authorization: `Bearer ${token}` },
      });
      return { status: response.status, body: await response.json() };
    }, adminKey);
    expect(managedAgents.status).toBe(200);
    expect(managedAgents.body).toEqual([expect.objectContaining({ id: createdAgentId, self: false })]);

    foreignAgent = await createAgentFixture(page);
    if (!foreignAgent) throw new Error('Could not create an isolated Agent fixture.');
    const foreignStatus = await page.evaluate(
      async ({ token, id }) => {
        const response = await fetch(`/api/v1/agents/${encodeURIComponent(id)}/tokens`, {
          credentials: 'omit',
          headers: { authorization: `Bearer ${token}` },
        });
        return response.status;
      },
      { token: adminKey, id: foreignAgent.agentId },
    );
    expect(foreignStatus).toBe(404);

    const tokens = await page.evaluate(
      async ({ token, id }) => {
        const response = await fetch(`/api/v1/agents/${encodeURIComponent(id)}/tokens`, {
          credentials: 'omit',
          headers: { authorization: `Bearer ${token}` },
        });
        return { status: response.status, body: await response.json() };
      },
      { token: adminKey, id: createdAgentId },
    );
    expect(tokens.status).toBe(200);
    expect(tokens.body).toEqual([expect.objectContaining({ tokenId: agent.body.tokenId })]);

    const rotated = await page.evaluate(
      async ({ token, id, tokenId }) => {
        const response = await fetch(
          `/api/v1/agents/${encodeURIComponent(id)}/tokens/${encodeURIComponent(tokenId)}/rotate`,
          { method: 'POST', credentials: 'omit', headers: { authorization: `Bearer ${token}` } },
        );
        return { status: response.status, body: await response.json() };
      },
      { token: adminKey, id: createdAgentId, tokenId: agent.body.tokenId },
    );
    expect(rotated.status).toBe(201);
    expect(rotated.body.token).toMatch(/^agt_/);

    const revoked = await page.evaluate(
      async ({ token, id, tokenId }) => {
        const response = await fetch(`/api/v1/agents/${encodeURIComponent(id)}/tokens/${encodeURIComponent(tokenId)}`, {
          method: 'DELETE',
          credentials: 'omit',
          headers: { authorization: `Bearer ${token}` },
        });
        return response.status;
      },
      { token: adminKey, id: createdAgentId, tokenId: rotated.body.tokenId },
    );
    expect(revoked).toBe(204);
  } finally {
    const cleanup = async (action: () => Promise<void>) => {
      try {
        await action();
      } catch (error) {
        cleanupErrors.push(error);
      }
    };
    if (foreignAgent) await cleanup(() => deleteAgentFixture(page, foreignAgent!));
    if (createdAgentId) {
      await cleanup(async () => {
        const status = await page.evaluate(
          async (id) => (await fetch(`/api/v1/admin/users/${encodeURIComponent(id)}`, { method: 'DELETE' })).status,
          createdAgentId,
        );
        if (status !== 200) throw new Error(`Could not clean up Admin key-created Agent (${status}).`);
      });
    }
    if (clientId) {
      await cleanup(async () => {
        const status = await page.evaluate(
          async (id) => (await fetch(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, { method: 'DELETE' })).status,
          clientId,
        );
        if (status !== 204) throw new Error(`Could not clean up Admin key test app (${status}).`);
      });
    }
    await cleanup(() => deleteAdminFixture(page, administrator));
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Admin key Agent test cleanup failed.');
  }
});
