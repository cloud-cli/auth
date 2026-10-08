import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../assets/ui/tokens.html', import.meta.url), 'utf8');
const component = source.split('<template component="dashboard-auth-api-tokens"')[1];

test('Auth API token overview loads metadata per OIDC app and identifies its app', () => {
  assert.match(component, /apps\.value\.map\(async \(app\) =>/);
  assert.match(component, /getAuthApiTokens\(app\.id\)/);
  assert.match(component, /entry\.appId/);
  assert.match(component, /result\.tokens === null/);
});

test('Auth API token dashboard retains app-scoped create and revoke flows', () => {
  assert.match(component, /createAuthApiToken\(selected\.value, tokenLabel\.value\.trim\(\)\)/);
  assert.match(component, /revokeAuthApiToken\(entry\.appId, entry\.token\.tokenId\)/);
  assert.match(component, /Copy this Auth API token now\. It is only shown once\./);
  assert.doesNotMatch(component, /entry\.token\.token\b/);
  assert.equal((component.match(/for="entry of visibleTokens"/g) || []).length, 1);
  assert.match(component, /No Auth API tokens exist for this app\./);
});
