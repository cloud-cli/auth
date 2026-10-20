import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent } from './agent-fixture.js';

test('v2 navigation, profile, and dashboard sections render cleanly', async ({ page }) => {
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/me');
    await expect(page.locator('html')).toHaveClass(/dark/);
    await expect(page.getByRole('heading', { name: 'Your profile' })).toBeVisible();
    await expect(page.locator('#nav-menu')).toBeVisible();
    await expect(page.locator('#nav-menu').getByText('Management', { exact: true })).toHaveCount(0);
    await expect(page.locator('#sidebar').getByText('auth', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Profile' })).toBeVisible();
    await expect(page.locator('#nav-menu button[data-target="security"]')).toHaveCount(0);
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
    await expect(page.locator('main')).toHaveCSS('padding-top', '16px');
    await expect(page.locator('#sidebar')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    await expect(page.locator('main > header')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    await expect(page.locator('main > header')).toHaveCSS('border-bottom-width', '0px');
    const profileNavLink = page.locator('#sidebar button[data-target="profile"]');
    await expect(profileNavLink).toHaveCSS('background-color', 'rgb(28, 42, 32)');
    await expect(profileNavLink).toHaveCSS('color', 'rgb(215, 237, 200)');
    await profileNavLink.hover();
    await expect(profileNavLink).toHaveCSS('background-color', 'rgb(28, 42, 32)');
    await expect(profileNavLink).toHaveCSS('border-top-color', 'rgb(65, 107, 72)');
    await expect(profileNavLink.locator('lucide-icon')).toHaveCSS('color', 'rgb(200, 230, 168)');
    await page.getByRole('button', { name: 'Switch to light theme' }).click();
    await expect(profileNavLink).toHaveCSS('background-color', 'rgb(255, 255, 255)');
    await expect(profileNavLink).toHaveCSS('border-top-color', 'rgb(30, 58, 47)');
    await expect(profileNavLink).toHaveCSS('color', 'rgb(30, 58, 47)');
    await expect(profileNavLink.locator('lucide-icon')).toHaveCSS('color', 'rgb(30, 58, 47)');
    await profileNavLink.hover();
    await expect(profileNavLink).toHaveCSS('background-color', 'rgb(255, 255, 255)');
    await page.getByRole('button', { name: 'Switch to dark theme' }).click();
    await page.mouse.move(0, 0);
    await expect(page.locator('main > div.bg-white')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
    await expect(page.locator('#theme-toggle')).toHaveCSS('background-color', 'rgb(23, 33, 27)');
    await page.goto('/me#profile');
    await expect(page.locator('.v2-profile-identity')).toHaveCSS('background-color', 'rgb(25, 37, 29)');

    for (const [hash, heading] of [
      ['profile', 'Your profile'],
      ['properties', 'Properties'],
      ['applications', 'Applications'],
      ['agents', 'Agents'],
      ['tokens', 'Tokens'],
    ]) {
      await page.goto(`/me#${hash}`);
      await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    }

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/me#applications');
    await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
    await expect(page.locator('#nav-menu lucide-icon svg').first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    const menuButton = page.getByRole('button', { name: 'Open menu' });
    await expect(menuButton).toBeVisible();
    await expect(menuButton.locator('svg')).toBeVisible();
    await menuButton.click();
    await expect(page.locator('#sidebar')).toHaveClass(/translate-x-0/);
    await expect(page.getByRole('button', { name: 'Close menu' })).toBeVisible();
    await page.getByRole('button', { name: 'Tokens' }).click();
    await expect(page.getByRole('heading', { name: 'Tokens' })).toBeVisible();
    await expect(page.locator('#sidebar')).toHaveClass(/-translate-x-full/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});

test('theme toggle follows system preference and persists explicit choice', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    await page.goto('/me');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('html')).toHaveClass(/dark/);
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
    const toggle = page.getByRole('button', { name: 'Switch to light theme' });
    await expect(toggle).toBeVisible();
    await expect(page.locator('header lucide-icon[icon="chevron-down"]')).toHaveCount(0);

    await toggle.click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('html')).not.toHaveClass(/dark/);
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(238, 242, 236)');
    await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
    expect(await page.evaluate(() => localStorage.getItem('auth-theme'))).toBe('light');

    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('html')).not.toHaveClass(/dark/);
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(238, 242, 236)');
    await page.getByRole('button', { name: 'Switch to dark theme' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('html')).toHaveClass(/dark/);
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(14, 21, 17)');
    await page.evaluate(() => localStorage.removeItem('auth-theme'));
    await page.emulateMedia({ colorScheme: 'light' });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
    await page.emulateMedia({ colorScheme: 'dark' });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.getByRole('button', { name: 'Switch to light theme' })).toBeVisible();
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});
