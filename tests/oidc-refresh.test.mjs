import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

test('OIDC refresh tokens are hashed, rotated once, and replay revokes their family', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'auth-oidc-refresh-'));
  const adapterPath = path.join(directory, 'database.mjs');
  const previousDatabaseUrl = process.env.DATABASE_URL;
  await writeFile(
    adapterPath,
    `import { DatabaseSync } from 'node:sqlite';
const database = new DatabaseSync(':memory:');
export const all = async (sql, params = []) => database.prepare(sql).all(...params);
export const get = async (sql, params = []) => database.prepare(sql).get(...params);
export const run = async (sql, params = []) => {
  const result = database.prepare(sql).run(...params);
  return { changes: Number(result.changes) };
};
export const exec = async (sql) => database.exec(sql);
`,
  );
  process.env.DATABASE_URL = pathToFileURL(adapterPath).href;

  try {
    const { default: migrate } = await import('../dist/db/migrations/008_oidc_refresh_tokens.js');
    await migrate();
    const oidc = await import('../dist/src/oidc.js');
    const { one, run } = await import('../dist/src/database.js');
    const scopes = ['openid', 'profile', 'offline_access'];
    const original = await oidc.createInitialRefreshToken('consumer', 'user-1', scopes);
    const originalHash = createHash('sha256').update(original).digest('hex');
    const stored = await one('SELECT * FROM auth_oidc_refresh_token WHERE token_hash = ?', [originalHash]);
    assert.ok(stored);
    assert.equal(JSON.stringify(stored).includes(original), false);

    assert.equal(await oidc.rotateRefreshToken(original, 'another-client'), null);
    assert.equal(await oidc.rotateRefreshToken(original, 'consumer', ['openid', 'admin']), 'invalid_scope');
    assert.equal(await oidc.rotateRefreshToken(original, 'consumer', ['profile']), 'invalid_scope');
    const refreshed = await oidc.rotateRefreshToken(original, 'consumer');
    assert.ok(refreshed);
    assert.notEqual(refreshed.refreshToken, original);
    assert.deepEqual(refreshed.scopes, scopes);

    assert.equal(await oidc.rotateRefreshToken(original, 'another-client'), null);
    await oidc.revokeRefreshToken(original, 'another-client');
    const validNext = await oidc.rotateRefreshToken(refreshed.refreshToken, 'consumer');
    assert.ok(validNext);

    assert.equal(await oidc.rotateRefreshToken(original, 'consumer'), null);
    assert.equal(await oidc.rotateRefreshToken(validNext.refreshToken, 'consumer'), null);

    const narrowedOriginal = await oidc.createInitialRefreshToken('consumer', 'user-6', scopes);
    const narrowed = await oidc.rotateRefreshToken(narrowedOriginal, 'consumer', ['openid']);
    assert.ok(narrowed);
    assert.deepEqual(narrowed.scopes, ['openid']);
    assert.equal(narrowed.refreshToken, undefined);

    const revocable = await oidc.createInitialRefreshToken('consumer', 'user-2', scopes);
    await oidc.revokeRefreshToken(revocable, 'consumer');
    assert.equal(await oidc.rotateRefreshToken(revocable, 'consumer'), null);

    const rotatedRevocable = await oidc.createInitialRefreshToken('consumer', 'user-3', scopes);
    const rotated = await oidc.rotateRefreshToken(rotatedRevocable, 'consumer');
    assert.ok(rotated);
    await oidc.revokeRefreshToken(rotatedRevocable, 'consumer');
    assert.equal(await oidc.rotateRefreshToken(rotated.refreshToken, 'consumer'), null);

    const expired = await oidc.createInitialRefreshToken('consumer', 'user-4', scopes);
    const expiredHash = createHash('sha256').update(expired).digest('hex');
    await run('UPDATE auth_oidc_refresh_token SET expires_at = ? WHERE token_hash = ?', [
      new Date(Date.now() - 1000).toISOString(),
      expiredHash,
    ]);
    assert.equal(await oidc.rotateRefreshToken(expired, 'consumer'), null);

    const concurrent = await oidc.createInitialRefreshToken('consumer', 'user-5', scopes);
    const outcomes = await Promise.all([
      oidc.rotateRefreshToken(concurrent, 'consumer'),
      oidc.rotateRefreshToken(concurrent, 'consumer'),
    ]);
    for (const outcome of outcomes.filter(Boolean))
      assert.equal(await oidc.rotateRefreshToken(outcome.refreshToken, 'consumer'), null);
    const concurrentHash = createHash('sha256').update(concurrent).digest('hex');
    const family = await one(
      'SELECT revoked_at FROM auth_oidc_refresh_token, json_each(auth_oidc_refresh_token.previous_hashes) WHERE json_each.value = ?',
      [concurrentHash],
    );
    assert.ok(family?.revoked_at);
  } finally {
    if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previousDatabaseUrl;
    await rm(directory, { recursive: true, force: true });
  }
});
