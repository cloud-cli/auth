import type { BrowserContext, Page } from '@playwright/test';

export type AgentFixture = { agentId: string; token: string };
export type AdminFixture = { userId: string };

const contextsWithLi3Route = new WeakSet<BrowserContext>();

export async function allowLocalLi3Imports(page: Page) {
  const baseURL = process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000';
  if (new URL(baseURL).hostname !== '127.0.0.1' || contextsWithLi3Route.has(page.context())) return;

  contextsWithLi3Route.add(page.context());
  await page.context().route('https://cdn.li3.dev/**', async (route) => {
    const response = await route.fetch({
      headers: { ...route.request().headers(), origin: 'https://auth.lab.apphor.de' },
    });
    await route.fulfill({ response, headers: { ...response.headers(), 'access-control-allow-origin': '*' } });
  });
}

export async function createAdminFixture(page: Page): Promise<AdminFixture | null> {
  await allowLocalLi3Imports(page);
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const response = await fetch('/__test__/admin-session', { method: 'POST' });
    return { status: response.status, body: response.ok ? await response.json() : null };
  });
  if (result.status === 404) return null;
  if (result.status !== 201) throw new Error(`Could not create administrator test fixture (${result.status}).`);
  return result.body;
}

export async function deleteAdminFixture(page: Page, fixture: AdminFixture) {
  const status = await page.evaluate(
    async (userId) => (await fetch(`/__test__/admins/${encodeURIComponent(userId)}`, { method: 'DELETE' })).status,
    fixture.userId,
  );
  if (status !== 204) throw new Error(`Could not clean up administrator fixture (${status}).`);
}

export async function createAgentFixture(page: Page): Promise<AgentFixture | null> {
  await allowLocalLi3Imports(page);
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const response = await fetch('/__test__/agents', { method: 'POST' });
    return { status: response.status, body: response.ok ? await response.json() : null };
  });
  if (result.status === 404) return null;
  if (result.status !== 201) throw new Error(`Could not create Agent test fixture (${result.status}).`);
  return result.body;
}

export async function signInAsAgent(page: Page, fixture: AgentFixture, returnUrl = '/me') {
  await page.goto(`/login?url=${encodeURIComponent(returnUrl)}`);
  await page.getByText('Sign in as an Agent', { exact: true }).click();
  await page.getByLabel('Agent ID').fill(fixture.agentId);
  await page.getByLabel('Sign-in token').fill(fixture.token);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL((url) => url.pathname === new URL(returnUrl, url.origin).pathname);
}

export async function deleteAgentFixture(page: Page, fixture: AgentFixture) {
  const status = await page.evaluate(
    async (agentId) => (await fetch(`/__test__/agents/${encodeURIComponent(agentId)}`, { method: 'DELETE' })).status,
    fixture.agentId,
  );
  if (status !== 204) throw new Error(`Could not clean up Agent fixture (${status}).`);
}
