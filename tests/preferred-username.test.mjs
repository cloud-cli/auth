import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizePreferredUsername } from '../dist/src/user.js';

test('preferred usernames are trimmed, case-normalized, and constrained', () => {
  assert.equal(normalizePreferredUsername('  Alice_9 '), 'alice_9');
  for (const invalid of ['', ' has spaces ', '-starts-hyphen', 'x'.repeat(31), 'ümlaut']) {
    assert.throws(() => normalizePreferredUsername(invalid), /Username must/);
  }
  assert.throws(() => normalizePreferredUsername(42), /Username must be a string/);
});
