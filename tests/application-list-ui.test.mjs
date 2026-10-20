import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const appEditor = await readFile('assets/ui/dashboard-app-editor.html', 'utf8');
const applications = await readFile('assets/ui/dashboard-applications.html', 'utf8');

test('empty callback and post-logout sections are hidden from non-managers', () => {
  assert.match(appEditor, /if="admin \|\| \(app\.redirectUris && app\.redirectUris\.length > 0\)"/);
  assert.match(appEditor, /if="admin \|\| \(app\.postLogoutRedirectUris && app\.postLogoutRedirectUris\.length > 0\)"/);
});

test('Published and Private badges retain compact padding and typography', () => {
  assert.match(applications, /class="rounded-full px-2 py-0\.5 text-xxs font-semibold"/);
  assert.match(
    applications,
    /bind-class="\{ 'app-visibility-published': app\.availableToUsers, 'app-visibility-private': !app\.availableToUsers \}"/,
  );
  assert.doesNotMatch(applications, /attr-class="app\.availableToUsers/);
  assert.doesNotMatch(applications, /<code if="app\.name !== app\.id"/);
});
