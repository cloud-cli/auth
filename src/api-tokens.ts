import { createHash, randomBytes } from 'crypto';
import { ApiToken, json, rows, run } from './database.js';
import { getClient, verifyClientSecret } from './oidc.js';

const ttl = 365 * 24 * 60 * 60 * 1000;

function hash(token: string) {
  return createHash('sha256').update(token).digest('base64url');
}

export async function createApiToken(userId: string, clientId: string, label: string, scopes: string[]) {
  const client = await getClient(clientId);
  if (!client) throw new Error('Unknown OIDC client');
  const allowed = new Set(client.scopes || []);
  if (!scopes.length || scopes.some((scope) => !allowed.has(scope))) throw new Error('Invalid token scope');
  const token = 'apphor_' + randomBytes(32).toString('base64url');
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

export async function listApiTokens(userId: string, clientId: string) {
  const tokens = await rows<ApiToken>('auth_api_token', 'user_id = ? AND client_id = ?', [userId, clientId]);
  return tokens.map(({ label, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }) => ({
    label,
    scopes,
    createdAt,
    expiresAt,
    lastUsedAt,
    revokedAt,
  }));
}

export async function revokeApiToken(userId: string, clientId: string, label: string) {
  const tokens = await rows<ApiToken>('auth_api_token', 'user_id = ? AND client_id = ? AND label = ?', [
    userId,
    clientId,
    label,
  ]);
  if (!tokens[0]) return false;
  tokens[0].revokedAt = new Date().toISOString();
  await run('UPDATE auth_api_token SET revoked_at = ? WHERE token_hash = ?', [
    tokens[0].revokedAt,
    tokens[0].tokenHash,
  ]);
  return true;
}

export async function introspectApiToken(token: string, clientId: string, clientSecret: string) {
  const client = await getClient(clientId);
  if (!client || !(await verifyClientSecret(client, clientSecret))) return null;
  const tokens = await rows<ApiToken>('auth_api_token', 'token_hash = ? AND client_id = ?', [hash(token), clientId]);
  const item = tokens[0];
  if (!item || item.revokedAt || Date.parse(item.expiresAt) <= Date.now()) return { active: false };
  item.lastUsedAt = new Date().toISOString();
  await run('UPDATE auth_api_token SET last_used_at = ? WHERE token_hash = ?', [item.lastUsedAt, item.tokenHash]);
  return {
    active: true,
    client_id: item.clientId,
    sub: item.userId,
    scope: item.scopes.join(' '),
    token_type: 'Bearer',
    iat: Math.floor(Date.parse(item.createdAt) / 1000),
    exp: Math.floor(Date.parse(item.expiresAt) / 1000),
  };
}
