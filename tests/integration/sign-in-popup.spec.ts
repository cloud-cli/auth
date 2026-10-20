import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture } from './agent-fixture.js';
const authOrigin = process.env.INTEGRATION_BASE_URL || 'http://localhost:3000';

// Auth Lab's address-space policy is not under test; this spec focuses on popup messaging.
test.use({
  launchOptions: {
    args: ['--disable-web-security'],
  },
});

test('popup sign-in returns the profile to an allowed consumer and closes itself', async ({ page }) => {
  const setupPage = await page.context().newPage();
  const fixture = await createAgentFixture(setupPage);
  await setupPage.close();
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }
  const runtimeErrors: string[] = [];
  page.on('pageerror', (error) => runtimeErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') runtimeErrors.push(message.text());
  });

  const consumerOrigin = authOrigin.startsWith('https://') ? 'https://consumer.lab.apphor.de' : 'http://localhost:3101';
  const authModuleUrl = new URL('/index.mjs', authOrigin).href;
  await page.route(`${consumerOrigin}/**`, (route) =>
    route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><button id="signin">Sign in</button><output id="state"></output><script type="module">
        import { events, signIn } from ${JSON.stringify(authModuleUrl)};
        window.authLoaded = true;
        events.addEventListener('state', ({ detail }) => {
          if (detail) document.querySelector('#state').textContent = detail.id;
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
  await popup.getByText('Try another way', { exact: true }).click();
  await popup.getByText('Sign in as an Agent', { exact: true }).click();
  await popup.getByLabel('Agent ID').fill(fixture.agentId);
  await popup.getByLabel('Sign-in token').fill(fixture.token);
  await popup.getByRole('button', { name: 'Sign in' }).click();

  try {
    await expect(page.locator('#state')).toHaveText(fixture.agentId);
    await expect.poll(() => popup.isClosed()).toBe(true);
  } finally {
    const cleanupPage = await page.context().newPage();
    await deleteAgentFixture(cleanupPage, fixture);
    await cleanupPage.close();
  }
});
