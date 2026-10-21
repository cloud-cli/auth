import { createHash, randomBytes } from 'crypto';
import { all, rows, run, saveUser, User } from './database.js';
import { isUserSuspended } from './user.js';
import { revokeRefreshTokensForClient, revokeRefreshTokensForUser } from './oidc.js';

const agentTokenLifetimeMs = 365 * 24 * 60 * 60 * 1000;

export type Agent = {
  userId: string;
  createdByUserId: string;
  rootOwnerUserId: string;
  name: string;
  createdAt: string;
};

export type AgentToken = {
  tokenHash: string;
  tokenHint: string;
  userId: string;
  label: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string;
  revokedAt: string;
};

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('base64url');
}

function normalizeName(value: unknown) {
  if (typeof value !== 'string') {
    throw new Error('Agent name must be a string.');
  }
  const name = value.trim();
  if (!name || name.length > 40 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error('Agent name must be between 1 and 40 printable characters.');
  }
  return name;
}

function normalizeTokenLabel(value: unknown) {
  if (typeof value !== 'string') {
    throw new Error('Token label must be a string.');
  }
  const label = value.trim();
  if (!label || label.length > 80 || /[\u0000-\u001f\u007f]/.test(label)) {
    throw new Error('Token label must be between 1 and 80 printable characters.');
  }
  return label;
}

export async function getAgent(userId: string) {
  return (await rows<Agent>('auth_agent', 'user_id = ?', [userId]))[0] || null;
}

export async function createAgent(createdByUserId: string, value: unknown) {
  const name = normalizeName(value);
  const creatorRows = await rows<User>('auth_user', 'user_id = ?', [createdByUserId]);
  const creator = creatorRows[0];
  if (!creator || (await isUserSuspended(createdByUserId))) {
    throw new Error('The creating account is unavailable.');
  }

  let rootOwnerUserId = createdByUserId;
  if (creator.role === 'agent') {
    const parent = await getAgent(createdByUserId);
    if (!parent || (await isUserSuspended(parent.rootOwnerUserId))) {
      throw new Error('The creating Agent is unavailable.');
    }
    rootOwnerUserId = parent.rootOwnerUserId;
  }

  const createdAt = new Date().toISOString();
  const userId = `agent_${randomBytes(12).toString('base64url')}`;
  const user: User = {
    userId,
    profileId: `agent-profile-${randomBytes(16).toString('hex')}`,
    accessToken: '',
    refreshToken: '',
    name,
    email: '',
    photo: '',
    lastSeen: createdAt,
    role: 'agent',
  };

  await saveUser(user);
  try {
    const inserted = await run(
      `INSERT INTO auth_agent (user_id, created_by_user_id, root_owner_user_id, name, created_at)
       SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM auth_agent WHERE created_by_user_id = ?) < 20`,
      [userId, createdByUserId, rootOwnerUserId, name, createdAt, createdByUserId],
    );
    if (!inserted?.changes) {
      throw new Error('An account can create up to 20 Agents.');
    }
    const credential = await createAgentToken(userId, 'Initial sign-in token');
    return {
      agent: { userId, createdByUserId, rootOwnerUserId, name, createdAt },
      ...credential,
    };
  } catch (error) {
    await run('DELETE FROM auth_agent_token WHERE user_id = ?', [userId]);
    await run('DELETE FROM auth_agent WHERE user_id = ?', [userId]);
    await run('DELETE FROM auth_user WHERE user_id = ?', [userId]);
    throw error;
  }
}

export async function createAgentToken(userId: string, labelValue: unknown) {
  const agent = await getAgent(userId);
  if (!agent || (await isUserSuspended(userId)) || (await isUserSuspended(agent.rootOwnerUserId))) {
    throw new Error('Agent is unavailable.');
  }

  const label = normalizeTokenLabel(labelValue);
  const token = `agt_${randomBytes(32).toString('base64url')}`;
  const tokenHash = hashToken(token);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + agentTokenLifetimeMs).toISOString();
  const tokenHint = `${token.slice(0, 7)}...${token.slice(-4)}`;
  await run(
    'INSERT INTO auth_agent_token (token_hash, token_hint, user_id, label, created_at, expires_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [tokenHash, tokenHint, userId, label, createdAt, expiresAt, '', ''],
  );
  return { token, tokenId: tokenHash, tokenHint, label, createdAt, expiresAt };
}

export async function verifyAgentToken(userId: string, token: string) {
  if (!token || !token.startsWith('agt_')) {
    return false;
  }
  const candidateHash = hashToken(token);
  const item = (
    await rows<AgentToken>('auth_agent_token', 'token_hash = ? AND user_id = ?', [candidateHash, userId])
  )[0];
  if (!item || item.revokedAt || Date.parse(item.expiresAt) <= Date.now()) {
    return false;
  }
  const agent = await getAgent(userId);
  if (!agent || (await isUserSuspended(userId)) || (await isUserSuspended(agent.rootOwnerUserId))) {
    return false;
  }
  await run('UPDATE auth_agent_token SET last_used_at = ? WHERE token_hash = ?', [
    new Date().toISOString(),
    candidateHash,
  ]);
  return true;
}

export async function listAgentsForUser(userId: string, role: User['role']) {
  if (role === 'admin') {
    return all<Agent & { disabled: number }>(
      `SELECT auth_agent.user_id AS userId, auth_agent.created_by_user_id AS createdByUserId,
              auth_agent.root_owner_user_id AS rootOwnerUserId, auth_agent.name, auth_agent.created_at AS createdAt,
              auth_user.disabled
       FROM auth_agent JOIN auth_user ON auth_user.user_id = auth_agent.user_id
       ORDER BY auth_agent.created_at DESC`,
    );
  }

  const filter =
    role === 'agent'
      ? `auth_agent.user_id IN (
           WITH RECURSIVE descendants(user_id) AS (
             SELECT user_id FROM auth_agent WHERE created_by_user_id = ?
             UNION ALL
             SELECT auth_agent.user_id FROM auth_agent JOIN descendants ON auth_agent.created_by_user_id = descendants.user_id
           ) SELECT user_id FROM descendants
         )`
      : 'root_owner_user_id = ?';
  return all<
    Agent & {
      disabled: number;
    }
  >(
    `SELECT auth_agent.user_id AS userId, auth_agent.created_by_user_id AS createdByUserId,
            auth_agent.root_owner_user_id AS rootOwnerUserId, auth_agent.name, auth_agent.created_at AS createdAt,
            auth_user.disabled
     FROM auth_agent JOIN auth_user ON auth_user.user_id = auth_agent.user_id
     WHERE ${filter} ORDER BY auth_agent.created_at DESC`,
    [userId],
  );
}

export async function listAgentsForAdminKey(ownerUserId: string, role: User['role']) {
  return listAgentsForUser(ownerUserId, role === 'agent' ? 'agent' : 'user');
}

export async function canManageAgent(actorUserId: string, targetUserId: string) {
  const target = await getAgent(targetUserId);
  if (!target) {
    return false;
  }
  const actor = (await rows<User>('auth_user', 'user_id = ?', [actorUserId]))[0];
  if (actor?.role === 'admin') {
    return true;
  }
  if (target.createdByUserId === actorUserId) {
    return true;
  }
  if (actor?.role === 'agent') {
    return (await managedAgentTree(actorUserId)).includes(targetUserId);
  }
  return target.rootOwnerUserId === actorUserId;
}

export async function canManageAgentWithAdminKey(ownerUserId: string, ownerRole: User['role'], targetUserId: string) {
  const target = await getAgent(targetUserId);
  if (!target || targetUserId === ownerUserId) return false;
  if (ownerRole === 'agent') {
    return (
      target.rootOwnerUserId === (await getAgent(ownerUserId))?.rootOwnerUserId &&
      (await managedAgentTree(ownerUserId)).includes(targetUserId)
    );
  }
  return target.rootOwnerUserId === ownerUserId;
}

export async function listAgentTokens(userId: string) {
  return (await rows<AgentToken>('auth_agent_token', 'user_id = ?', [userId])).map(
    ({ tokenHash, tokenHint, label, createdAt, expiresAt, lastUsedAt, revokedAt }) => ({
      tokenId: tokenHash,
      tokenHint,
      label,
      createdAt,
      expiresAt,
      lastUsedAt,
      revokedAt,
    }),
  );
}

export async function revokeAgentToken(userId: string, tokenId: string) {
  const revokedAt = new Date().toISOString();
  const result = await run(
    "UPDATE auth_agent_token SET revoked_at = ? WHERE user_id = ? AND token_hash = ? AND revoked_at = ''",
    [revokedAt, userId, tokenId],
  );
  return Boolean(result?.changes);
}

export async function rotateAgentToken(userId: string, tokenId: string) {
  const token = (
    await rows<AgentToken>('auth_agent_token', "user_id = ? AND token_hash = ? AND revoked_at = ''", [userId, tokenId])
  )[0];
  if (!token || Date.parse(token.expiresAt) <= Date.now()) {
    return null;
  }

  const replacement = await createAgentToken(userId, token.label);
  if (!(await revokeAgentToken(userId, tokenId))) {
    await revokeAgentToken(userId, replacement.tokenId);
    throw new Error('The original sign-in token could not be revoked.');
  }
  return replacement;
}

export async function managedAgentTree(userId: string) {
  return all<{ user_id: string }>(
    `WITH RECURSIVE descendants(user_id) AS (
       SELECT user_id FROM auth_agent WHERE user_id = ?
       UNION ALL
       SELECT auth_agent.user_id FROM auth_agent JOIN descendants ON auth_agent.created_by_user_id = descendants.user_id
     ) SELECT user_id FROM descendants`,
    [userId],
  ).then((items) => items.map((item) => item.user_id));
}

export async function disableAgentTree(userId: string) {
  const agentIds = await managedAgentTree(userId);
  if (!agentIds.length) {
    return [];
  }
  const placeholders = agentIds.map(() => '?').join(', ');
  await run(`UPDATE auth_user SET disabled = 1 WHERE user_id IN (${placeholders})`, agentIds);
  await run(`UPDATE auth_agent_token SET revoked_at = ? WHERE user_id IN (${placeholders}) AND revoked_at = ''`, [
    new Date().toISOString(),
    ...agentIds,
  ]);
  for (const agentId of agentIds) await revokeRefreshTokensForUser(agentId);

  const sessions = await all<{ sid: string; session: string }>('SELECT sid, session FROM auth_session');
  for (const item of sessions) {
    try {
      if (agentIds.includes(JSON.parse(item.session)?.passport?.user)) {
        await run('DELETE FROM auth_session WHERE sid = ?', [item.sid]);
      }
    } catch {}
  }
  return agentIds;
}

export async function disableAgentsForRootOwner(rootOwnerUserId: string) {
  const agents = await rows<Agent>('auth_agent', 'root_owner_user_id = ?', [rootOwnerUserId]);
  const disabled = new Set<string>();
  for (const agent of agents) {
    if (disabled.has(agent.userId)) {
      continue;
    }
    for (const id of await disableAgentTree(agent.userId)) disabled.add(id);
  }
  return [...disabled];
}

export async function deleteAgentData(userIds: string[]) {
  if (!userIds.length) {
    return;
  }
  const placeholders = userIds.map(() => '?').join(', ');
  await run(`DELETE FROM auth_agent_token WHERE user_id IN (${placeholders})`, userIds);
  await run(`DELETE FROM auth_agent WHERE user_id IN (${placeholders})`, userIds);
  await run(`DELETE FROM auth_user WHERE user_id IN (${placeholders})`, userIds);
}

export async function deleteAgentTree(userId: string) {
  const agentIds = await managedAgentTree(userId);
  if (!agentIds.length) {
    return [];
  }
  const sessions = await all<{ sid: string; session: string }>('SELECT sid, session FROM auth_session');
  for (const item of sessions) {
    try {
      if (agentIds.includes(JSON.parse(item.session)?.passport?.user)) {
        await run('DELETE FROM auth_session WHERE sid = ?', [item.sid]);
      }
    } catch {}
  }
  for (const agentId of agentIds) {
    const clients = await rows<{ id: string }>('auth_oidc_client', 'owner_user_id = ?', [agentId]);
    for (const client of clients) {
      await run('DELETE FROM auth_api_token WHERE client_id = ?', [client.id]);
      await revokeRefreshTokensForClient(client.id);
      await run('DELETE FROM auth_oidc_client WHERE id = ?', [client.id]);
    }
    await revokeRefreshTokensForUser(agentId);
    for (const table of ['auth_authenticator', 'auth_api_token', 'auth_property', 'auth_qr_login']) {
      await run(`DELETE FROM ${table} WHERE user_id = ?`, [agentId]);
    }
    await run('DELETE FROM auth_audit_event WHERE user_id = ?', [agentId]);
    await run(
      'DELETE FROM auth_blocked_identity WHERE profile_id = (SELECT profile_id FROM auth_user WHERE user_id = ?)',
      [agentId],
    );
  }
  await deleteAgentData(agentIds);
  return agentIds;
}
