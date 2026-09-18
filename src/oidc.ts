import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { json, OidcClient, User, rows, run } from './database.js';
import { accessTokenTtl, createAccessToken, createIdentityToken } from './token.js';

type Client = { id: string; redirectUris: string[]; scopes: string[]; secretHash: string };
type AuthorizationCode = { clientId: string; redirectUri: string; userId: string; codeChallenge: string; expiresAt: number };

const codes = new Map<string, AuthorizationCode>();

function isSecureRedirectUri(uri: string) {
  try {
    const url = new URL(uri);
    return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
  } catch {
    return false;
  }
}

function hashSecret(secret: string, salt = randomBytes(16)) {
  return `${salt.toString('base64url')}:${scryptSync(secret, salt, 32).toString('base64url')}`;
}

function matchesSecret(secret: string, stored: string) {
  const [encodedSalt, encodedHash] = stored.split(':');
  if (!encodedSalt || !encodedHash) return false;
  const actual = scryptSync(secret, Buffer.from(encodedSalt, 'base64url'), 32);
  const expected = Buffer.from(encodedHash, 'base64url');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function getClient(clientId: string) {
  try {
    const stored = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [clientId]))[0];
    return stored ? { id: stored.id, redirectUris: stored.redirectUris, scopes: stored.scopes || [], secretHash: stored.secretHash } as Client : undefined;
  } catch {
    return undefined;
  }
}

export async function isOidcClient(clientId: string) {
  return Boolean(await getClient(clientId));
}

export async function verifyClientSecret(client: Client, secret: string) {
  return matchesSecret(secret, client.secretHash);
}

export function createAuthorizationCode(client: Client, redirectUri: string, userId: string, codeChallenge: string) {
  const code = randomBytes(32).toString('base64url');
  codes.set(code, { clientId: client.id, redirectUri, userId, codeChallenge, expiresAt: Date.now() + 60_000 });
  return code;
}

export async function exchangeAuthorizationCode({ code, clientId, clientSecret, redirectUri, codeVerifier }: Record<string, string>) {
  const authorizationCode = codes.get(code);
  codes.delete(code);
  if (!authorizationCode || authorizationCode.expiresAt < Date.now()) return null;
  const client = await getClient(clientId);
  if (!client || authorizationCode.clientId !== clientId || authorizationCode.redirectUri !== redirectUri) return null;
  if (!matchesSecret(clientSecret, client.secretHash) || codeChallenge(codeVerifier) !== authorizationCode.codeChallenge) return null;
  return authorizationCode;
}

function codeChallenge(verifier: string) {
  return createHash('sha256').update(verifier).digest('base64url');
}

export async function tokenResponse(user: User, clientId: string) {
  return { access_token: await createAccessToken(user.userId, clientId), id_token: await createIdentityToken(user, clientId), token_type: 'Bearer', expires_in: accessTokenTtl() };
}

export async function listManagedClients() {
  const clients = await rows<OidcClient>('auth_oidc_client');
  return clients.map(({ id, redirectUris, scopes, createdAt }) => ({ id, redirectUris, scopes, createdAt }));
}

export async function createManagedClient(id: string, redirectUris: string[], scopes: string[]) {
  if (!id || !/^[a-zA-Z0-9._-]{1,80}$/.test(id)) throw new Error('Invalid client ID');
  const normalizedUris = redirectUris.filter(isSecureRedirectUri);
  if (!normalizedUris.length) throw new Error('At least one HTTPS redirect URI is required');
  const normalizedScopes = scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope));
  if (!normalizedScopes.length) throw new Error('At least one scope is required');
  if (await getClient(id)) throw new Error('Client already exists');
  const secret = randomBytes(32).toString('base64url');
  await run('INSERT INTO auth_oidc_client (id, secret_hash, redirect_uris, scopes, created_at) VALUES (?, ?, ?, ?, ?)', [id, hashSecret(secret), json(normalizedUris), json(normalizedScopes), new Date().toISOString()]);
  return { id, secret, redirectUris: normalizedUris, scopes: normalizedScopes };
}

export async function removeManagedClient(id: string) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) return false;
  await run('DELETE FROM auth_oidc_client WHERE id = ?', [id]);
  return true;
}

export async function addManagedClientScopes(id: string, scopes: string[]) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const additions = scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope));
  client.scopes = [...new Set([...(client.scopes || []), ...additions])];
  await run('UPDATE auth_oidc_client SET scopes = ? WHERE id = ?', [json(client.scopes), id]);
  return client.scopes;
}
