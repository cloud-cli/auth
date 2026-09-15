import { createHash, randomBytes } from 'crypto';
import { Query, Resource } from '@cloud-cli/store';
import { ApiToken } from './store.js';
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
  await new ApiToken({ tokenHash: hash(token), userId, clientId, scopes, label: label || 'API token', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + ttl).toISOString(), lastUsedAt: '', revokedAt: '' }).save();
  return { token, expiresAt: new Date(Date.now() + ttl).toISOString() };
}

export async function listApiTokens(userId: string, clientId: string) {
  const tokens = await Resource.find(ApiToken, new Query<ApiToken>().where('userId').is(userId).where('clientId').is(clientId));
  return tokens.map(({ label, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }) => ({ label, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }));
}

export async function revokeApiToken(userId: string, clientId: string, label: string) {
  const tokens = await Resource.find(ApiToken, new Query<ApiToken>().where('userId').is(userId).where('clientId').is(clientId).where('label').is(label));
  if (!tokens[0]) return false;
  tokens[0].revokedAt = new Date().toISOString();
  await tokens[0].save();
  return true;
}

export async function introspectApiToken(token: string, clientId: string, clientSecret: string) {
  const client = await getClient(clientId);
  if (!client || !(await verifyClientSecret(client, clientSecret))) return null;
  const tokens = await Resource.find(ApiToken, new Query<ApiToken>().where('tokenHash').is(hash(token)).where('clientId').is(clientId));
  const item = tokens[0];
  if (!item || item.revokedAt || Date.parse(item.expiresAt) <= Date.now()) return { active: false };
  item.lastUsedAt = new Date().toISOString();
  await item.save();
  return { active: true, client_id: item.clientId, sub: item.userId, scope: item.scopes.join(' '), token_type: 'Bearer', iat: Math.floor(Date.parse(item.createdAt) / 1000), exp: Math.floor(Date.parse(item.expiresAt) / 1000) };
}
