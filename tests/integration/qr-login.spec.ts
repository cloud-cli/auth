import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent, type AgentFixture } from './agent-fixture.js';

test('Agent accounts cannot approve QR sign-ins', async ({ browser }) => {
  const baseURL = process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000';
  const laptopContext = await browser.newContext({ baseURL });
  const phoneContext = await browser.newContext({ baseURL });
  let phone: Page | undefined;
  let fixture: AgentFixture | null = null;

  try {
    const laptop = await laptopContext.newPage();
    await laptop.goto('/qr-login?url=%2Fme');
    await expect(laptop.getByText('Waiting for approval on your phone...')).toBeVisible();
    expect((await laptopContext.cookies()).some((cookie) => cookie.name === 'connect.sid')).toBe(true);

    const pwaUrl = await laptop.getByRole('link', { name: 'Open Auth PWA' }).getAttribute('href');
    expect(pwaUrl).toBeTruthy();
    const transaction = new URL(pwaUrl!).searchParams.get('transaction');
    expect(transaction).toBeTruthy();

    phone = await phoneContext.newPage();
    fixture = await createAgentFixture(phone);
    if (!fixture) {
      test.skip(true, 'Requires a deployment built with test fixture routes');
      return;
    }
    await signInAsAgent(phone, fixture);

    const approvalStatus = await phone.evaluate(async (token) => {
      const response = await fetch('/api/v1/qr-login/approve', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: token }),
      });
      return response.status;
    }, transaction);
    expect(approvalStatus).toBe(403);
    await expect(laptop.getByText('Waiting for approval on your phone...')).toBeVisible();
  } finally {
    if (phone && fixture) await deleteAgentFixture(phone, fixture);
    await laptopContext.close();
    await phoneContext.close();
  }
});
