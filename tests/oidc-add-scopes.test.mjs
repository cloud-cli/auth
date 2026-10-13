import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

test('concurrent OIDC scope additions preserve all existing and newly added scopes', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'auth-oidc-scopes-'));
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
    const { default: migrate } = await import('../dist/db/migrations/006_add_oidc_logout_uris.js');
    await migrate();
    const oidc = await import('../dist/src/oidc.js');
    await oidc.createManagedClient('scope-test', ['https://scope-test.example/callback'], ['existing:read']);

    await Promise.all([
      oidc.addManagedClientScopes('scope-test', ['service-a:read']),
      oidc.addManagedClientScopes('scope-test', ['service-b:write']),
    ]);

    const client = await oidc.getClient('scope-test');
    assert.deepEqual(new Set(client.scopes), new Set(['existing:read', 'service-a:read', 'service-b:write']));

    const repeated = await oidc.addManagedClientScopes('scope-test', ['service-a:read', 'service-c:read']);
    assert.equal(repeated.filter((scope) => scope === 'service-a:read').length, 1);
    assert.ok(repeated.includes('existing:read'));
    assert.ok(repeated.includes('service-c:read'));

    const fullScopeList = Array.from({ length: 500 }, (_, index) => `service:${index}`);
    await oidc.updateManagedClientScopes('scope-test', fullScopeList);
    await assert.rejects(oidc.addManagedClientScopes('scope-test', ['service:additional']), /scope limit exceeded/);
    assert.deepEqual((await oidc.getClient('scope-test')).scopes, fullScopeList);
  } finally {
    if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previousDatabaseUrl;
    await rm(directory, { recursive: true, force: true });
  }
});
