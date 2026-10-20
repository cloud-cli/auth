import { expect, test } from '@playwright/test';
import { createAdminFixture, deleteAdminFixture } from './agent-fixture.js';

test('administrator signing keys and Auth API tokens are under Recovery codes in Security', async ({ page }) => {
  const fixture = await createAdminFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await page.goto('/me#security');
    await expect(page.getByRole('heading', { name: 'Recovery codes' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Signing keys' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Auth API tokens' })).toBeVisible();
    const headings = await page.locator('section.content-section h2').allTextContents();
    expect(headings.indexOf('Recovery codes')).toBeLessThan(headings.indexOf('Signing keys'));

    const apps = await page.evaluate(async () => {
      const result = [];
      for (const [name, host] of [
        ['Security tokens app A', 'security-a.example'],
        ['Security tokens app B', 'security-b.example'],
      ]) {
        const response = await fetch('/api/v1/oidc/clients', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name, redirectUris: [`https://${host}/callback`] }),
        });
        if (!response.ok) throw new Error('Could not create an Auth API token test app.');
        result.push(await response.json());
      }
      const tokenResponse = await fetch(`/api/v1/auth-api-tokens/${encodeURIComponent(result[1].id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'Token for second app' }),
      });
      if (!tokenResponse.ok) throw new Error('Could not create an Auth API token for the second app.');
      return result;
    });

    const appSelector = page.getByRole('combobox');
    await appSelector.selectOption(apps[0].id);
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(page.url()).origin });
    await page.getByPlaceholder('Token label').fill('Security Auth API token');
    await page.getByRole('button', { name: 'Generate Auth API token' }).click();
    const tokenField = page.getByRole('button', { name: 'Copy full value to clipboard' });
    await tokenField.click();
    const token = await page.evaluate(() => navigator.clipboard.readText());
    expect(token).toMatch(/^auth_/);
    const preview = (await tokenField.innerText()).replace(/\s/g, '');
    expect(preview.endsWith(token.slice(-3))).toBe(true);
    expect(preview).not.toContain('…');
    await expect(page.getByText('Security Auth API token', { exact: true })).toBeVisible();

    await appSelector.selectOption('');
    await expect(page.getByText('Token for second app', { exact: true })).toBeVisible();
    await expect(page.getByText(`App: ${apps[1].id}`, { exact: true })).toBeVisible();
    await expect(page.getByText('Security Auth API token', { exact: true })).toBeVisible();
    await appSelector.selectOption(apps[1].id);
    await expect(page.getByText('Security Auth API token', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Token for second app', { exact: true })).toBeVisible();

    await appSelector.selectOption(apps[0].id);
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Revoke', exact: true }).click();
    await expect(page.getByText('Security Auth API token', { exact: true })).toHaveCount(0);
  } finally {
    await deleteAdminFixture(page, fixture);
  }
});
