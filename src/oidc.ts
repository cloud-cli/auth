import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { User } from './store.js';
import { accessTokenTtl, createAccessToken, createIdentityToken } from './token.js';

type Client = { id: string; redirectUris: string[]; secret: string };
type AuthorizationCode = { clientId: string; redirectUri: string; userId: string; codeChallenge: string; expiresAt: number };

const codes = new Map<string, AuthorizationCode>();
const clients = new Map<string, Client>();

try {
  const configuredClients = JSON.parse(process.env.OIDC_CLIENTS || '[]');
  if (Array.isArray(configuredClients)) {
    for (const client of configuredClients) {
      if (typeof client?.id !== 'string' || typeof client?.secret !== 'string' || !Array.isArray(client.redirectUris)) continue;
      const redirectUris = client.redirectUris.filter((uri: unknown) => typeof uri === 'string' && isSecureRedirectUri(uri));
      if (redirectUris.length) clients.set(client.id, { id: client.id, secret: client.secret, redirectUris });
    }
  }
} catch {
  // Invalid client configuration leaves OIDC disabled until it is corrected.
}

function isSecureRedirectUri(uri: string) {
  try {
    const url = new URL(uri);
    return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
  } catch {
    return false;
  }
}

export function getClient(clientId: string) {
  return clients.get(clientId);
}

export function isOidcClient(clientId: string) {
  return clients.has(clientId);
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
  const client = getClient(clientId);
  if (!client || authorizationCode.clientId !== clientId || authorizationCode.redirectUri !== redirectUri) return null;
  if (!sameSecret(client.secret, clientSecret) || codeChallenge(codeVerifier) !== authorizationCode.codeChallenge) return null;

  return authorizationCode;
}

function sameSecret(expected: string, actual: string) {
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);
  return expectedBuffer.length === actualBuffer.length && timingSafeEqual(expectedBuffer, actualBuffer);
}

function codeChallenge(verifier: string) {
  return createHash('sha256').update(verifier).digest('base64url');
}

export async function tokenResponse(user: User, clientId: string) {
  return {
    access_token: await createAccessToken(user.userId, clientId),
    id_token: await createIdentityToken(user, clientId),
    token_type: 'Bearer',
    expires_in: accessTokenTtl(),
  };
}
