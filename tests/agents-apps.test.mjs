import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

test('Agents have independent credentials and owner-scoped private OIDC apps', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'auth-agents-apps-'));
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
    const { default: migrate } = await import('../dist/db/migrations/010_agents.js');
    await migrate();
    const database = await import('../dist/src/database.js');
    const agents = await import('../dist/src/agents.js');
    const oidc = await import('../dist/src/oidc.js');
    const apiTokens = await import('../dist/src/api-tokens.js');
    const now = new Date().toISOString();
    const owner = {
      userId: 'human-owner',
      profileId: 'human-owner-profile',
      accessToken: '',
      refreshToken: '',
      name: 'Owner',
      email: 'owner@example.test',
      photo: '',
      lastSeen: now,
      role: 'user',
    };
    const other = { ...owner, userId: 'other-user', profileId: 'other-profile', email: 'other@example.test' };
    const admin = {
      ...owner,
      userId: 'admin-user',
      profileId: 'admin-profile',
      email: 'admin@example.test',
      role: 'admin',
    };
    await database.saveUser(owner);
    await database.saveUser(other);
    await database.saveUser(admin);

    const parent = await agents.createAgent(owner.userId, 'Build agent');
    const child = await agents.createAgent(parent.agent.userId, 'Child agent');
    assert.notEqual(parent.agent.userId, owner.userId);
    assert.notEqual(parent.agent.userId, child.agent.userId);
    assert.equal(parent.agent.rootOwnerUserId, owner.userId);
    assert.equal(child.agent.createdByUserId, parent.agent.userId);
    assert.equal(await agents.verifyAgentToken(parent.agent.userId, parent.token), true);
    assert.equal(await agents.canManageAgent(owner.userId, child.agent.userId), true);
    assert.equal(await agents.canManageAgent(parent.agent.userId, child.agent.userId), true);
    assert.equal(await agents.canManageAgent(child.agent.userId, parent.agent.userId), false);
    assert.equal(await agents.canManageAgent(admin.userId, child.agent.userId), true);
    assert.deepEqual(
      new Set((await agents.listAgentsForUser(owner.userId, owner.role)).map((agent) => agent.userId)),
      new Set([parent.agent.userId, child.agent.userId]),
    );
    assert.deepEqual(
      (await agents.listAgentsForUser(parent.agent.userId, 'agent')).map((agent) => agent.userId),
      [child.agent.userId],
    );

    const replacement = await agents.rotateAgentToken(parent.agent.userId, parent.tokenId);
    assert.equal(await agents.verifyAgentToken(parent.agent.userId, parent.token), false);
    assert.equal(await agents.verifyAgentToken(parent.agent.userId, replacement.token), true);

    const privateApp = await oidc.createManagedClient(
      'Private agent app',
      ['https://agent.example/callback'],
      ['agent:read'],
      false,
      [],
      parent.agent.userId,
      false,
    );
    const adminKey = await apiTokens.createAuthApiToken(privateApp.id, 'Agent management key');
    const adminKeyPrincipal = await apiTokens.authenticateAdminKey(adminKey.token);
    assert.deepEqual(adminKeyPrincipal, {
      clientId: privateApp.id,
      ownerUserId: parent.agent.userId,
      ownerRole: 'agent',
    });
    assert.equal(await agents.canManageAgentWithAdminKey(parent.agent.userId, 'agent', child.agent.userId), true);
    assert.equal(await agents.canManageAgentWithAdminKey(parent.agent.userId, 'agent', parent.agent.userId), false);
    assert.equal(await agents.canManageAgentWithAdminKey(other.userId, 'user', child.agent.userId), false);
    assert.deepEqual(
      (await agents.listAgentsForAdminKey(parent.agent.userId, 'agent')).map((agent) => agent.userId),
      [child.agent.userId],
    );
    const adminKeyMetadata = (await apiTokens.listAuthApiTokens(privateApp.id)).find(
      (item) => item.label === 'Agent management key',
    );
    assert.ok(adminKeyMetadata);
    await apiTokens.revokeApiToken(privateApp.id, privateApp.id, adminKeyMetadata.tokenId);
    assert.equal(await apiTokens.authenticateAdminKey(adminKey.token), null);
    const publishedApp = await oidc.createManagedClient(
      'Published app',
      ['https://published.example/callback'],
      ['published:read'],
      false,
      [],
      owner.userId,
      true,
    );
    const privateUserApp = await oidc.createManagedClient(
      'Private user app',
      ['https://agent.example/callback'],
      ['user:read'],
      false,
      [],
      owner.userId,
      false,
    );
    assert.match(privateApp.id, /^app_[A-Za-z0-9_-]+$/);
    assert.notEqual(privateApp.id, privateApp.name);
    assert.deepEqual(
      (await oidc.listAvailableClients(parent.agent.userId)).map((app) => app.id).sort(),
      [privateApp.id, publishedApp.id].sort(),
    );
    assert.equal(
      (await oidc.listAvailableClients(parent.agent.userId)).find((app) => app.id === privateApp.id).canManage,
      true,
    );
    assert.equal(
      (await oidc.listAvailableClients(other.userId)).some((app) => app.id === privateApp.id),
      false,
    );
    assert.equal(
      (await oidc.listAvailableClients(other.userId)).some((app) => app.id === publishedApp.id),
      true,
    );
    assert.equal(
      (await oidc.listAvailableClients(owner.userId)).some((app) => app.id === privateUserApp.id),
      true,
    );
    assert.equal(
      (await oidc.listAvailableClients(other.userId)).some((app) => app.id === privateUserApp.id),
      false,
    );
    assert.equal((await oidc.listAvailableClients(admin.userId, true)).length, 3);

    const downstreamToken = await apiTokens.createApiToken(parent.agent.userId, privateApp.id, 'Agent API token', [
      'agent:read',
    ]);
    assert.match(downstreamToken.token, /^auth_/);
    assert.deepEqual((await apiTokens.listApiTokens(parent.agent.userId))[0].scopes, ['agent:read']);
    assert.deepEqual(await apiTokens.listApiTokens(other.userId), []);

    await oidc.updateManagedClientName(privateApp.id, 'Renamed private app');
    assert.equal((await oidc.getClient(privateApp.id)).name, 'Renamed private app');
    await oidc.updateManagedClientAvailability(privateApp.id, true);
    assert.equal(
      (await oidc.listAvailableClients(other.userId)).some((app) => app.id === privateApp.id),
      true,
    );
  } finally {
    if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previousDatabaseUrl;
    await rm(directory, { recursive: true, force: true });
  }
});
