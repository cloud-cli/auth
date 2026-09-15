import { getDb } from '../db/connector.js';

export type User = {
  userId: string;
  profileId: string;
  profile?: unknown;
  accessToken: string;
  refreshToken: string;
  name: string;
  email: string;
  photo: string;
  lastSeen: string;
  recoveryCodes?: string[];
};

export type UserProperty = { uid: string; userId: string; key: string; value: unknown };
export type UserSession = { sid: string; session: any };
export type Authenticator = { credentialId: string; userId: string; publicKey: string; counter: number; transports: string[]; label: string; createdAt: string; lastUsedAt: string; revokedAt: string };
export type QrLoginTransaction = { token: string; sessionId: string; returnUrl: string; createdAt: string; userId: string; status: string };
export type OidcClient = { id: string; secretHash: string; redirectUris: string[]; scopes: string[]; createdAt: string };
export type ApiToken = { tokenHash: string; userId: string; clientId: string; scopes: string[]; label: string; createdAt: string; expiresAt: string; lastUsedAt: string; revokedAt: string };
export type AuditEvent = { id: string; userId: string; event: string; app: string; result: string; timestamp: string; redirectUri: string };
export type SigningKey = { kid: string; encryptedPrivateKey: string; publicKey: string; status: string; createdAt: string };

const jsonColumns = new Set(['profile', 'recovery_codes', 'session', 'transports', 'redirect_uris', 'scopes']);
const tableColumns: Record<string, Record<string, string>> = {
  auth_user: { userId: 'user_id', profileId: 'profile_id', accessToken: 'access_token', refreshToken: 'refresh_token', lastSeen: 'last_seen', recoveryCodes: 'recovery_codes' },
  auth_property: { uid: 'uid', userId: 'user_id', key: 'key', value: 'value' },
  auth_session: { sid: 'sid', session: 'session' },
  auth_authenticator: { credentialId: 'credential_id', userId: 'user_id', publicKey: 'public_key', createdAt: 'created_at', lastUsedAt: 'last_used_at', revokedAt: 'revoked_at' },
  auth_qr_login: { token: 'token', sessionId: 'session_id', returnUrl: 'return_url', createdAt: 'created_at', userId: 'user_id', status: 'status' },
  auth_oidc_client: { id: 'id', secretHash: 'secret_hash', redirectUris: 'redirect_uris', scopes: 'scopes', createdAt: 'created_at' },
  auth_api_token: { tokenHash: 'token_hash', userId: 'user_id', clientId: 'client_id', scopes: 'scopes', createdAt: 'created_at', expiresAt: 'expires_at', lastUsedAt: 'last_used_at', revokedAt: 'revoked_at' },
  auth_audit_event: { id: 'id', userId: 'user_id', event: 'event', app: 'app', result: 'result', timestamp: 'timestamp', redirectUri: 'redirect_uri' },
  auth_signing_key: { kid: 'kid', encryptedPrivateKey: 'encrypted_private_key', publicKey: 'public_key', status: 'status', createdAt: 'created_at' },
};

function decode(value: unknown) {
  if (value === null || value === undefined || value === '') return value;
  try { return JSON.parse(String(value)); } catch { return value; }
}

function mapRow(table: string, row: Record<string, any>) {
  const mapping = tableColumns[table];
  const result: Record<string, any> = { ...row };
  for (const [camel, column] of Object.entries(mapping || {})) {
    result[camel] = column === 'value' && row.value_type === 'json' ? decode(row[column]) : jsonColumns.has(column) ? decode(row[column]) : row[column];
    if (camel !== column) delete result[column];
  }
  return result;
}

export async function all<T>(sql: string, params: unknown[] = []) {
  const db = await getDb();
  return (await db.all(sql, params)) as T[];
}

export async function one<T>(sql: string, params: unknown[] = []) {
  const db = await getDb();
  const row = await db.get(sql, params);
  return row ? row as T : undefined;
}

export async function run(sql: string, params: unknown[] = []) {
  const db = await getDb();
  return db.run(sql, params);
}

export async function rows<T>(table: string, where = '', params: unknown[] = []) {
  return (await all<Record<string, any>>(`SELECT * FROM ${table}${where ? ` WHERE ${where}` : ''}`, params)).map((row) => mapRow(table, row)) as T[];
}

export function json(value: unknown) {
  return value === undefined || value === null ? null : JSON.stringify(value);
}

export async function initDatabase() {
  await getDb();
}

export async function saveUser(user: User) {
  await run('INSERT OR REPLACE INTO auth_user (user_id, profile_id, profile, access_token, refresh_token, name, email, photo, last_seen, recovery_codes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [user.userId, user.profileId || '', json(user.profile), user.accessToken || '', user.refreshToken || '', user.name || '', user.email || '', user.photo || '', user.lastSeen || '', json(user.recoveryCodes)]);
}

export async function saveAuthenticator(item: Authenticator) {
  await run('INSERT OR REPLACE INTO auth_authenticator (credential_id, user_id, public_key, counter, transports, label, created_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [item.credentialId, item.userId, item.publicKey, item.counter, json(item.transports), item.label, item.createdAt, item.lastUsedAt, item.revokedAt]);
}
