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

test('application management controls are inside the expandable details row', () => {
  const detailsStart = applications.indexOf('<details class="min-w-0"');
  const summaryEnd = applications.indexOf('</summary>', detailsStart);
  const secretButton = applications.indexOf('aria-label="Regenerate secret"', summaryEnd);
  const deleteButton = applications.indexOf('aria-label="Delete application"', summaryEnd);
  const publishButton = applications.indexOf('Publish\n                  </button>', summaryEnd);
  const detailsEnd = applications.indexOf('</details>', detailsStart);

  assert.ok(detailsStart >= 0);
  assert.ok(summaryEnd > detailsStart);
  assert.ok(secretButton > summaryEnd && secretButton < detailsEnd);
  assert.ok(deleteButton > summaryEnd && deleteButton < detailsEnd);
  assert.ok(publishButton > summaryEnd && publishButton < detailsEnd);
});
