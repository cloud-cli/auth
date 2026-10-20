import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../assets/ui/dashboard-api-tokens.html', import.meta.url), 'utf8');
const component = source.split('<template component="v2-api-tokens"')[1];

test('revoked downstream tokens follow active tokens under a separate heading', () => {
  const activeList = component.indexOf('for="token of activeTokens"');
  const revokedHeading = component.indexOf('Revoked tokens');
  const revokedList = component.indexOf('for="token of revokedTokens"');

  assert.notEqual(activeList, -1);
  assert.ok(activeList < revokedHeading);
  assert.ok(revokedHeading < revokedList);
  assert.match(component, /activeTokens\.value = matchingTokens\.filter\(\(token\) => !token\.revokedAt\)/);
  assert.match(component, /revokedTokens\.value = matchingTokens\.filter\(\(token\) => Boolean\(token\.revokedAt\)\)/);
  assert.match(component, /\{\{ token\.clientId \}\}/);
});
