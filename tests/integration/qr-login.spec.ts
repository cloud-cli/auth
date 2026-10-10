import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];

test('phone approval completes QR sign-in on a fresh laptop session', async ({ browser }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const baseURL = process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000';
  const laptopContext = await browser.newContext({ baseURL });
  const phoneContext = await browser.newContext({ baseURL });

  try {
    const laptop = await laptopContext.newPage();
    await laptop.goto('/qr-login?url=%2Fme');
    await expect(laptop.getByText('Waiting for approval on your phone...')).toBeVisible();
    expect((await laptopContext.cookies()).some((cookie) => cookie.name === 'connect.sid')).toBe(true);

    const pwaUrl = await laptop.getByRole('link', { name: 'Open Auth PWA' }).getAttribute('href');
    expect(pwaUrl).toBeTruthy();
    const transaction = new URL(pwaUrl!).searchParams.get('transaction');
    expect(transaction).toBeTruthy();

    const phone = await phoneContext.newPage();
    await phone.goto('/');
    const loginStatus = await phone.evaluate(async (key) => {
      const response = await fetch('/__test__/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key }),
      });
      return response.status;
    }, testKey);
    expect(loginStatus).toBe(204);

    const approvalStatus = await phone.evaluate(async (token) => {
      const response = await fetch('/api/v1/qr-login/approve', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: token }),
      });
      return response.status;
    }, transaction);
    expect(approvalStatus).toBe(204);

    await expect(laptop).toHaveURL(/\/me$/, { timeout: 10_000 });
    await expect(laptop.getByRole('button', { name: 'Toggle profile details' })).toBeVisible();
  } finally {
    await laptopContext.close();
    await phoneContext.close();
  }
});
