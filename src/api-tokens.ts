import { createHash, randomBytes } from 'crypto';
import { ApiToken, json, rows, run } from './database.js';
import { getClient, verifyClientSecret } from './oidc.js';

const ttl = 365 * 24 * 60 * 60 * 1000;
export const authTokenManagementScope = 'auth:tokens:write';

function hash(token: string) {
  return createHash('sha256').update(token).digest('base64url');
}

export async function createApiToken(userId: string, clientId: string, label: string, scopes: string[]) {
  const client = await getClient(clientId);
  if (!client) throw new Error('Unknown OIDC client');
  const allowed = new Set(client.scopes || []);
  if (!scopes.length || scopes.some((scope) => !allowed.has(scope))) throw new Error('Invalid token scope');
  const token = 'auth_' + randomBytes(32).toString('base64url');
  await run(
    'INSERT OR REPLACE INTO auth_api_token (token_hash, user_id, client_id, scopes, label, created_at, expires_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      hash(token),
      userId,
      clientId,
      json(scopes),
      label || 'API token',
      new Date().toISOString(),
      new Date(Date.now() + ttl).toISOString(),
      '',
      '',
    ],
  );
  return { token, expiresAt: new Date(Date.now() + ttl).toISOString() };
}

export async function createAuthApiToken(clientId: string, label: string) {
  const client = await getClient(clientId);
  if (!client) throw new Error('Unknown OIDC client');
  const token = 'auth_' + randomBytes(32).toString('base64url');
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + ttl).toISOString();
  await run(
    'INSERT INTO auth_api_token (token_hash, user_id, client_id, scopes, label, created_at, expires_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      hash(token),
      clientId,
      clientId,
      json([authTokenManagementScope]),
      label || 'Auth API token',
      createdAt,
      expiresAt,
      '',
      '',
    ],
  );
  return { token, expiresAt };
}

export async function listAuthApiTokens(clientId: string) {
  const tokens = await rows<ApiToken>('auth_api_token', 'user_id = ? AND client_id = ?', [clientId, clientId]);
  return tokens
    .filter((token) => token.scopes.length === 1 && token.scopes[0] === authTokenManagementScope)
    .map(({ tokenHash, label, createdAt, expiresAt, lastUsedAt, revokedAt }) => ({
      tokenId: tokenHash,
      label,
      scopes: [authTokenManagementScope],
      createdAt,
      expiresAt,
      lastUsedAt,
      revokedAt,
    }));
}

export async function verifyAuthApiToken(token: string, clientId: string) {
  const item = (
    await rows<ApiToken>('auth_api_token', 'token_hash = ? AND client_id = ? AND user_id = ?', [
      hash(token),
      clientId,
      clientId,
    ])
  )[0];
  if (
    !item ||
    item.revokedAt ||
    Date.parse(item.expiresAt) <= Date.now() ||
    item.scopes.length !== 1 ||
    item.scopes[0] !== authTokenManagementScope
  ) {
    return false;
  }
  await run('UPDATE auth_api_token SET last_used_at = ? WHERE token_hash = ?', [
    new Date().toISOString(),
    item.tokenHash,
  ]);
  return true;
}

export async function listApiTokens(userId: string, clientId?: string) {
  const allowedScopes = clientId ? new Set((await getClient(clientId))?.scopes || []) : new Set();
  const filter = clientId ? 'user_id = ? AND client_id = ?' : 'user_id = ?';
  const params = clientId ? [userId, clientId] : [userId];
  const tokens = await rows<ApiToken>('auth_api_token', filter, params);
  return tokens.map(({ tokenHash, label, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }) => ({
    tokenId: tokenHash,
    label,
    scopes: clientId ? scopes.filter((scope) => allowedScopes.has(scope)) : scopes,
    createdAt,
    expiresAt,
    lastUsedAt,
    revokedAt,
  }));
}

export async function revokeApiToken(userId: string, clientId: string, tokenId: string) {
  const revokedAt = new Date().toISOString();
  const tokens = await rows<ApiToken>('auth_api_token', 'user_id = ? AND client_id = ? AND token_hash = ?', [
    userId,
    clientId,
    tokenId,
  ]);
  if (!tokens[0]) return false;
  await run('UPDATE auth_api_token SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND token_hash = ?', [
    revokedAt,
    userId,
    clientId,
    tokenId,
  ]);
  return true;
}

export async function revokePresentedApiToken(token: string, clientId: string) {
  const tokenHash = hash(token);
  const tokens = await rows<ApiToken>('auth_api_token', 'token_hash = ? AND client_id = ?', [tokenHash, clientId]);
  if (!tokens[0]) return false;
  await run('UPDATE auth_api_token SET revoked_at = ? WHERE token_hash = ? AND client_id = ?', [
    new Date().toISOString(),
    tokenHash,
    clientId,
  ]);
  return true;
}

export async function introspectApiToken(token: string, clientId: string, clientSecret: string) {
  const client = await getClient(clientId);
  if (!client || !(await verifyClientSecret(client, clientSecret))) return null;
  const tokens = await rows<ApiToken>('auth_api_token', 'token_hash = ? AND client_id = ?', [hash(token), clientId]);
  const item = tokens[0];
  if (!item || item.revokedAt || Date.parse(item.expiresAt) <= Date.now()) return { active: false };
  const allowed = new Set(client.scopes || []);
  const scopes = item.scopes.filter((scope) => allowed.has(scope));
  if (!scopes.length) return { active: false };
  item.lastUsedAt = new Date().toISOString();
  await run('UPDATE auth_api_token SET last_used_at = ? WHERE token_hash = ?', [item.lastUsedAt, item.tokenHash]);
  return {
    active: true,
    client_id: item.clientId,
    sub: item.userId,
    scope: scopes.join(' '),
    token_type: 'Bearer',
    iat: Math.floor(Date.parse(item.createdAt) / 1000),
    exp: Math.floor(Date.parse(item.expiresAt) / 1000),
  };
}
