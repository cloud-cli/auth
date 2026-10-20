import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { json, OidcClient, User, rows, run, one } from './database.js';
import { accessTokenTtl, createAccessToken, createIdentityToken } from './token.js';

type Client = {
  id: string;
  name: string;
  ownerUserId: string;
  availableToUsers: boolean;
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
          name: stored.name || stored.id,
          ownerUserId: stored.ownerUserId || '',
          availableToUsers: Boolean(stored.availableToUsers),
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
  return (
    scopes.includes('openid') &&
    scopes.every((scope) => ['openid', 'profile', 'email', 'offline_access'].includes(scope))
  );
}

type RefreshRow = {
  family_id: string;
  token_hash: string;
  previous_hashes: string;
  user_id: string;
  client_id: string;
  scopes: string;
  expires_at: string;
  revoked_at: string;
};
const refreshLifetimeMs = 30 * 24 * 60 * 60 * 1000;

export async function rotateRefreshToken(token: string | undefined, clientId: string, requestedScopes?: string[]) {
  if (!token) throw new Error('Refresh token is required');
  const hash = createHash('sha256').update(token).digest('hex');
  const now = new Date().toISOString();
  const row = await one<RefreshRow>('SELECT * FROM auth_oidc_refresh_token WHERE token_hash = ?', [hash]);
  if (!row) {
    const reused = await one<{ family_id: string }>(
      'SELECT family_id FROM auth_oidc_refresh_token, json_each(auth_oidc_refresh_token.previous_hashes) WHERE json_each.value = ? AND client_id = ?',
      [hash, clientId],
    );
    if (reused) await revokeRefreshTokenFamily(reused.family_id);
    return null;
  }
  if (row.client_id !== clientId || row.revoked_at || Date.parse(row.expires_at) <= Date.now()) return null;
  const grantedScopes = JSON.parse(row.scopes) as string[];
  const scopes = requestedScopes || grantedScopes;
  if (!scopes.includes('openid') || scopes.some((scope) => !grantedScopes.includes(scope))) return 'invalid_scope';
  const refreshToken = randomBytes(32).toString('base64url');
  const nextHash = createHash('sha256').update(refreshToken).digest('hex');
  const consumed = await run(
    "UPDATE auth_oidc_refresh_token SET previous_hashes = json_insert(previous_hashes, '$[#]', token_hash), token_hash = ?, scopes = ? WHERE family_id = ? AND token_hash = ? AND revoked_at = '' AND expires_at > ?",
    [nextHash, json(scopes), row.family_id, hash, now],
  );
  if (!consumed?.changes) {
    const reused = await one<{ family_id: string }>(
      'SELECT family_id FROM auth_oidc_refresh_token, json_each(auth_oidc_refresh_token.previous_hashes) WHERE json_each.value = ? AND client_id = ?',
      [hash, clientId],
    );
    if (reused) await revokeRefreshTokenFamily(reused.family_id);
    return null;
  }
  const current = await one<RefreshRow>('SELECT * FROM auth_oidc_refresh_token WHERE family_id = ?', [row.family_id]);
  if (!current || current.revoked_at) return null;
  if (!scopes.includes('offline_access')) await revokeRefreshTokenFamily(row.family_id);
  return {
    userId: current.user_id,
    familyId: current.family_id,
    scopes,
    refreshToken: scopes.includes('offline_access') ? refreshToken : undefined,
  };
}

export async function createInitialRefreshToken(clientId: string, userId: string, scopes: string[]) {
  const refreshToken = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(refreshToken).digest('hex');
  const family = randomBytes(16).toString('hex');
  await run(
    'INSERT INTO auth_oidc_refresh_token (family_id, token_hash, user_id, client_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
    [family, hash, userId, clientId, json(scopes), new Date(Date.now() + refreshLifetimeMs).toISOString()],
  );
  return refreshToken;
}

export async function revokeRefreshToken(token: string, clientId: string) {
  const hash = createHash('sha256').update(token).digest('hex');
  const revoked = await run(
    "UPDATE auth_oidc_refresh_token SET revoked_at = ? WHERE token_hash = ? AND client_id = ? AND revoked_at = ''",
    [new Date().toISOString(), hash, clientId],
  );
  if (revoked?.changes) return;
  const historical = await one<{ family_id: string }>(
    'SELECT family_id FROM auth_oidc_refresh_token, json_each(auth_oidc_refresh_token.previous_hashes) WHERE json_each.value = ? AND client_id = ?',
    [hash, clientId],
  );
  if (historical) await revokeRefreshTokenFamily(historical.family_id);
}

export async function revokeRefreshTokenFamily(familyId: string) {
  await run("UPDATE auth_oidc_refresh_token SET revoked_at = ? WHERE family_id = ? AND revoked_at = ''", [
    new Date().toISOString(),
    familyId,
  ]);
}

export async function revokeRefreshTokensForClient(clientId: string) {
  await run("UPDATE auth_oidc_refresh_token SET revoked_at = ? WHERE client_id = ? AND revoked_at = ''", [
    new Date().toISOString(),
    clientId,
  ]);
}

export async function revokeRefreshTokensForUser(userId: string) {
  await run("UPDATE auth_oidc_refresh_token SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''", [
    new Date().toISOString(),
    userId,
  ]);
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
    access_token: await createAccessToken(
      user.userId,
      clientId,
      scopes.filter((scope) => scope !== 'offline_access'),
    ),
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
  return clients.map(
    ({
      id,
      name,
      ownerUserId,
      availableToUsers,
      redirectUris,
      postLogoutRedirectUris,
      scopes,
      createdAt,
      isPublic,
    }) => ({
      id,
      name: name || id,
      ownerUserId,
      availableToUsers: Boolean(availableToUsers),
      redirectUris,
      postLogoutRedirectUris: postLogoutRedirectUris || [],
      scopes,
      createdAt,
      isPublic,
    }),
  );
}

export async function listAvailableClients(userId: string, isAdmin = false) {
  const clients = await rows<OidcClient>('auth_oidc_client');
  return clients
    .map((client) => {
      const canManage = isAdmin || client.ownerUserId === userId;
      return {
        id: client.id,
        name: client.name || client.id,
        scopes: client.scopes || [],
        isPublic: Boolean(client.isPublic),
        availableToUsers: Boolean(client.availableToUsers),
        canManage,
        ...(canManage
          ? {
              ownerUserId: client.ownerUserId,
              redirectUris: client.redirectUris,
              postLogoutRedirectUris: client.postLogoutRedirectUris || [],
              createdAt: client.createdAt,
            }
          : {}),
      };
    })
    .filter((client) => isAdmin || client.availableToUsers || client.ownerUserId === userId);
}

export async function createManagedClient(
  nameValue: string,
  redirectUris: string[],
  scopes: string[],
  isPublic = false,
  postLogoutRedirectUris: string[] = [],
  ownerUserId = '',
  availableToUsers = false,
) {
  const name = nameValue.trim();
  if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error('Invalid application name');
  }
  const id = `app_${randomBytes(24).toString('base64url')}`;
  const normalizedUris = [
    ...new Set(redirectUris.filter((uri) => isSecureRedirectUri(uri) || (isPublic && isNativeRedirectUri(uri)))),
  ];
  if (!normalizedUris.length) {
    throw new Error('At least one secure callback URL is required');
  }
  const normalizedLogoutUris = [
    ...new Set(
      postLogoutRedirectUris.filter((uri) => isSecureRedirectUri(uri) || (isPublic && isNativeRedirectUri(uri))),
    ),
  ];
  const normalizedScopes = scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope));
  const secret = randomBytes(32).toString('base64url');
  const inserted = await run(
    `INSERT INTO auth_oidc_client (id, secret_hash, redirect_uris, post_logout_redirect_uris, scopes, created_at, is_public, owner_user_id, available_to_users, display_name)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
     WHERE ? = '' OR (SELECT COUNT(*) FROM auth_oidc_client WHERE owner_user_id = ?) < 25`,
    [
      id,
      isPublic ? '' : hashSecret(secret),
      json(normalizedUris),
      json(normalizedLogoutUris),
      json(normalizedScopes),
      new Date().toISOString(),
      isPublic ? 1 : 0,
      ownerUserId,
      availableToUsers ? 1 : 0,
      name,
      ownerUserId,
      ownerUserId,
    ],
  );
  if (!inserted?.changes) {
    throw new Error('An account can create up to 25 applications.');
  }
  return {
    id,
    name,
    secret: isPublic ? undefined : secret,
    redirectUris: normalizedUris,
    postLogoutRedirectUris: normalizedLogoutUris,
    scopes: normalizedScopes,
    isPublic,
  };
}

export async function updateManagedClientAvailability(id: string, availableToUsers: boolean) {
  const result = await run('UPDATE auth_oidc_client SET available_to_users = ? WHERE id = ?', [
    availableToUsers ? 1 : 0,
    id,
  ]);
  return Boolean(result?.changes);
}

export async function updateManagedClientName(id: string, nameValue: string) {
  const name = nameValue.trim();
  if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error('Invalid application name');
  }
  const result = await run('UPDATE auth_oidc_client SET display_name = ? WHERE id = ?', [name, id]);
  if (!result?.changes) {
    throw new Error('Client not found');
  }
  return name;
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
  await revokeRefreshTokensForClient(id);
  await run('DELETE FROM auth_oidc_client WHERE id = ?', [id]);
  return true;
}

export async function regenerateManagedClientSecret(id: string) {
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  if (client.isPublic) throw new Error('Public clients do not have a client secret');
  const secret = randomBytes(32).toString('base64url');
  await revokeRefreshTokensForClient(id);
  await run('UPDATE auth_oidc_client SET secret_hash = ? WHERE id = ?', [hashSecret(secret), id]);
  return { id, secret, redirectUris: client.redirectUris, scopes: client.scopes || [] };
}

export async function addManagedClientScopes(id: string, scopes: string[]) {
  const maxClientScopes = 500;
  const additions = [
    ...new Set(scopes.map((scope) => scope.trim()).filter((scope) => /^[a-zA-Z0-9:._-]{1,80}$/.test(scope))),
  ];
  await run(
    `UPDATE auth_oidc_client SET scopes = (
      SELECT json_group_array(scope) FROM (
        SELECT scope FROM (
          SELECT value AS scope, 0 AS source, CAST(key AS INTEGER) AS ordinal FROM json_each(auth_oidc_client.scopes)
          UNION ALL
          SELECT value AS scope, 1 AS source, CAST(key AS INTEGER) AS ordinal FROM json_each(?)
        ) GROUP BY scope ORDER BY MIN(source), MIN(ordinal)
      )
    ) WHERE id = ? AND (
      SELECT count(*) FROM (
        SELECT value FROM json_each(auth_oidc_client.scopes)
        UNION
        SELECT value FROM json_each(?)
      )
    ) <= ?`,
    [json(additions), id, json(additions), maxClientScopes],
  );
  const client = (await rows<OidcClient>('auth_oidc_client', 'id = ?', [id]))[0];
  if (!client) throw new Error('Client not found');
  const resultingScopes = client.scopes || [];
  if (additions.some((scope) => !resultingScopes.includes(scope))) throw new Error('Client scope limit exceeded');
  return resultingScopes;
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
