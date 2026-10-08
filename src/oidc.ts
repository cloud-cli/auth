import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { json, OidcClient, User, rows, run } from './database.js';
import { accessTokenTtl, createAccessToken, createIdentityToken } from './token.js';

type Client = {
  id: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  secretHash: string | null;
  isPublic: boolean;
};
type AuthorizationCode = {
  clientId: string;
  redirectUri: string;
  userId: string;
  codeChallenge: string;
  scopes: string[];
  nonce?: string;
  expiresAt: number;
};

const codes = new Map<string, AuthorizationCode>();

export function isSecureRedirectUri(uri: string) {
  try {
    const url = new URL(uri);
    return (
      url.protocol === 'https:' ||
      (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
    );
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
    return stored
      ? ({
          id: stored.id,
          redirectUris: stored.redirectUris,
          postLogoutRedirectUris: stored.postLogoutRedirectUris || [],
          scopes: stored.scopes || [],
          secretHash: stored.secretHash,
          isPublic: Boolean(stored.isPublic),
        } as Client)
      : undefined;
  } catch {
    return undefined;
  }
}

export async function isOidcClient(clientId: string) {
  return Boolean(await getClient(clientId));
}

export async function verifyClientSecret(client: Client, secret: string) {
  return Boolean(client.secretHash && matchesSecret(secret, client.secretHash));
}

export function validateAuthorizationScopes(requestedScopes: string[]) {
  const scopes = [...new Set(requestedScopes)];
  return scopes.includes('openid') && scopes.every((scope) => ['openid', 'profile', 'email'].includes(scope));
}

export function createAuthorizationCode(
  client: Client,
  redirectUri: string,
  userId: string,
  codeChallenge: string,
  scopes: string[] = ['openid'],
  nonce?: string,
) {
  if (!validateAuthorizationScopes(scopes)) throw new Error('Unsupported OIDC scope');
  const code = randomBytes(32).toString('base64url');
  codes.set(code, {
    clientId: client.id,
    redirectUri,
    userId,
    codeChallenge,
    scopes: [...new Set(scopes)],
    nonce,
    expiresAt: Date.now() + 60_000,
  });
  return code;
}

export async function exchangeAuthorizationCode({
  code,
  clientId,
  clientSecret,
  redirectUri,
  codeVerifier,
}: Record<string, string>) {
  const authorizationCode = codes.get(code);
  codes.delete(code);
  if (!authorizationCode || authorizationCode.expiresAt < Date.now()) return null;
  const client = await getClient(clientId);
  if (!client || authorizationCode.clientId !== clientId || authorizationCode.redirectUri !== redirectUri) return null;
  if (
    (client.isPublic
      ? Boolean(clientSecret)
      : !clientSecret || !client.secretHash || !matchesSecret(clientSecret, client.secretHash)) ||
    !validCodeVerifier(codeVerifier) ||
    codeChallenge(codeVerifier) !== authorizationCode.codeChallenge
  )
    return null;
  return authorizationCode;
}

function validCodeVerifier(verifier: string) {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(verifier);
}

function codeChallenge(verifier: string) {
  return createHash('sha256').update(verifier).digest('base64url');
}

export async function tokenResponse(user: User, clientId: string, scopes: string[] = ['openid'], nonce?: string) {
  const claims: Record<string, unknown> = {};
  if (scopes.includes('profile')) {
    claims.name = user.name;
    if (user.photo) {
      claims.picture = user.photo;
      claims.photo = user.photo;
    }
    if (user.preferredUsername) claims.preferred_username = user.preferredUsername;
  }
  if (scopes.includes('email')) claims.email = user.email;
  return {
    access_token: await createAccessToken(user.userId, clientId, scopes),
    id_token: await createIdentityToken(user, clientId, claims, nonce),
    scope: scopes.join(' '),
    token_type: 'Bearer',
    expires_in: accessTokenTtl(),
  };
}

export function oidcUserInfo(user: User, scopes: string[]) {
  return {
    sub: user.userId,
    ...(scopes.includes('profile')
      ? {
          name: user.name,
          ...(user.photo ? { picture: user.photo, photo: user.photo } : {}),
          ...(user.preferredUsername ? { preferred_username: user.preferredUsername } : {}),
        }
      : {}),
    ...(scopes.includes('email') ? { email: user.email } : {}),
  };
}

export async function listManagedClients() {
  const clients = await rows<OidcClient>('auth_oidc_client');
  return clients.map(({ id, redirectUris, postLogoutRedirectUris, scopes, createdAt, isPublic }) => ({
    id,
    redirectUris,
    postLogoutRedirectUris: postLogoutRedirectUris || [],
    scopes,
    createdAt,
    isPublic,
  }));
}

export async function createManagedClient(
  id: string,
  redirectUris: string[],
  scopes: string[],
  isPublic = false,
  postLogoutRedirectUris: string[] = [],
) {
  if (!id || !/^[a-zA-Z0-9._-]{1,80}$/.test(id)) throw new Error('Invalid client ID');
  const normalizedUris = [
    ...new Set(redirectUris.filter((uri) => isSecureRedirectUri(uri) || (isPublic && isNativeRedirectUri(uri)))),
  ];
  if (!normalizedUris.length) throw new Error('At least one secure callback URL is required');
  const normalizedLogoutUris = [
    ...new Set(
      postLogoutRedirectUris.filter((uri) => isSecureRedirectUri(uri) || (isPublic && isNativeRedirectUri(uri))),
    ),
  ];
  const normalizedScopes = scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope));
  if (await getClient(id)) throw new Error('Client already exists');
  const secret = randomBytes(32).toString('base64url');
  await run(
    'INSERT INTO auth_oidc_client (id, secret_hash, redirect_uris, post_logout_redirect_uris, scopes, created_at, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [
      id,
      isPublic ? '' : hashSecret(secret),
      json(normalizedUris),
      json(normalizedLogoutUris),
      json(normalizedScopes),
      new Date().toISOString(),
      isPublic ? 1 : 0,
    ],
  );
  return {
    id,
    secret: isPublic ? undefined : secret,
    redirectUris: normalizedUris,
    postLogoutRedirectUris: normalizedLogoutUris,
    scopes: normalizedScopes,
    isPublic,
  };
}

export function isNativeRedirectUri(uri: string) {
  try {
    const parsed = new URL(uri);
    return (
      /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/i.test(parsed.protocol) &&
      !['http:', 'https:', 'javascript:', 'data:'].includes(parsed.protocol)
    );
  } catch {
    return false;
  }
}

export async function updateManagedClientRedirectUris(id: string, redirectUris: string[]) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const normalizedUris = [
    ...new Set(redirectUris.filter((uri) => isSecureRedirectUri(uri) || (client.isPublic && isNativeRedirectUri(uri)))),
  ];
  await run('UPDATE auth_oidc_client SET redirect_uris = ? WHERE id = ?', [json(normalizedUris), id]);
  return normalizedUris;
}

export async function updateManagedClientPostLogoutRedirectUris(id: string, redirectUris: string[]) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const normalizedUris = [
    ...new Set(redirectUris.filter((uri) => isSecureRedirectUri(uri) || (client.isPublic && isNativeRedirectUri(uri)))),
  ];
  await run('UPDATE auth_oidc_client SET post_logout_redirect_uris = ? WHERE id = ?', [json(normalizedUris), id]);
  return normalizedUris;
}

export async function removeManagedClient(id: string) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) return false;
  // Remove credentials too, so recreating this client ID cannot revive old API tokens.
  await run('DELETE FROM auth_api_token WHERE client_id = ?', [id]);
  await run('DELETE FROM auth_oidc_client WHERE id = ?', [id]);
  return true;
}

export async function regenerateManagedClientSecret(id: string) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  if (client.isPublic) throw new Error('Public clients do not have a client secret');
  const secret = randomBytes(32).toString('base64url');
  await run('UPDATE auth_oidc_client SET secret_hash = ? WHERE id = ?', [hashSecret(secret), id]);
  return { id, secret, redirectUris: client.redirectUris, scopes: client.scopes || [] };
}

export async function addManagedClientScopes(id: string, scopes: string[]) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const additions = scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope));
  client.scopes = [...new Set([...(client.scopes || []), ...additions])];
  await run('UPDATE auth_oidc_client SET scopes = ? WHERE id = ?', [json(client.scopes), id]);
  return client.scopes;
}

export async function updateManagedClientScopes(id: string, scopes: string[]) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const normalizedScopes = [
    ...new Set(scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope))),
  ];
  await run('UPDATE auth_oidc_client SET scopes = ? WHERE id = ?', [json(normalizedScopes), id]);
  return normalizedScopes;
}
