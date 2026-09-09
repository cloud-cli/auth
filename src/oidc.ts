import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { Query, Resource } from '@cloud-cli/store';
import { OidcClient, User } from './store.js';
import { accessTokenTtl, createAccessToken, createIdentityToken } from './token.js';

type Client = { id: string; redirectUris: string[]; secretHash: string };
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
  const stored = await new OidcClient({ id: clientId }).find();
  if (stored) return { id: stored.id, redirectUris: stored.redirectUris, secretHash: stored.secretHash } as Client;
  return undefined;
}

export async function isOidcClient(clientId: string) {
  return Boolean(await getClient(clientId));
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
  const clients = await Resource.find(OidcClient, new Query<OidcClient>());
  return clients.map(({ id, redirectUris, createdAt }) => ({ id, redirectUris, createdAt }));
}

export async function createManagedClient(id: string, redirectUris: string[]) {
  if (!id || !/^[a-zA-Z0-9._-]{1,80}$/.test(id)) throw new Error('Invalid client ID');
  const normalizedUris = redirectUris.filter(isSecureRedirectUri);
  if (!normalizedUris.length) throw new Error('At least one HTTPS redirect URI is required');
  if (await getClient(id)) throw new Error('Client already exists');
  const secret = randomBytes(32).toString('base64url');
  await new OidcClient({ id, secretHash: hashSecret(secret), redirectUris: normalizedUris, createdAt: new Date().toISOString() }).save();
  return { id, secret, redirectUris: normalizedUris };
}

export async function removeManagedClient(id: string) {
  const client = await new OidcClient({ id }).find();
  if (!client) return false;
  await client.remove();
  return true;
}
