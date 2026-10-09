import { expect, test } from '@playwright/test';

const testKey = process.env.AUTH_TEST_SECRET || process.env.AUTH_TEST_KEYS?.split(',')[0];
const authOrigin = process.env.INTEGRATION_BASE_URL || 'http://localhost:3000';

// The fixture deliberately uses distinct loopback origins; disable Chromium's local-only
// private-network restriction so this can test application messaging rather than PNA policy.
test.use({
  launchOptions: {
    args: ['--disable-web-security'],
  },
});

test('popup sign-in returns the profile to an allowed consumer and closes itself', async ({ page }) => {
  test.skip(!testKey, 'Requires a test-enabled deployment');
  const runtimeErrors: string[] = [];
  page.on('pageerror', (error) => runtimeErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') runtimeErrors.push(message.text());
  });

  const consumerOrigin = 'http://localhost:3101';
  const authModuleUrl = new URL('/index.mjs', authOrigin).href;
  await page.route(`${consumerOrigin}/**`, (route) =>
    route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><button id="signin">Sign in</button><output id="state"></output><script type="module">
        import { events, signIn } from ${JSON.stringify(authModuleUrl)};
        window.authLoaded = true;
        events.addEventListener('state', ({ detail }) => {
          if (detail) document.querySelector('#state').textContent = detail.email;
        });
        document.querySelector('#signin').addEventListener('click', () => signIn(true));
      </script>`,
    }),
  );
  await page.goto(consumerOrigin);

  const popupPromise = page.waitForEvent('popup', { timeout: 5000 });
  await page.getByRole('button', { name: 'Sign in' }).click();
  const popup = await popupPromise.catch(async () => {
    const loaded = await page.evaluate(() => (window as Window & { authLoaded?: boolean }).authLoaded || false);
    throw new Error(`Popup did not open (moduleLoaded=${loaded}); ${runtimeErrors.join(' | ')}`);
  });
  await expect(popup).toHaveURL(/\/login\?/);
  await popup.getByLabel('Test API key').fill(testKey!);
  await popup.getByRole('button', { name: 'Sign in' }).click();

  await expect(page.locator('#state')).toContainText(/@example\.test/);
  await expect.poll(() => popup.isClosed()).toBe(true);
});
