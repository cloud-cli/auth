import { deepStrictEqual } from 'node:assert';
import { initStore, User, UserProperty, UserSession, Authenticator, QrLoginTransaction, OidcClient, ApiToken, AuditEvent, SigningKey } from '../../src/store.js';
import { Query, Resource } from '@cloud-cli/store';
import { getDb } from '../connector.js';
import upSchema from './001_create-db.js';

function encoded(value: unknown) {
  if (value === null || value === undefined) return { value: '', type: 'null' };
  if (typeof value === 'object') return { value: JSON.stringify(value), type: 'json' };
  return { value: String(value), type: typeof value };
}

function verify(expected: Record<string, unknown>, actual: Record<string, unknown>, fields: string[]) {
  for (const field of fields) deepStrictEqual(actual[field], expected[field], `Migration mismatch in ${field}`);
}

async function copy(db: any, model: any, select: string, insert: string, fields: string[], values: (item: any) => unknown[]) {
  const records = await Resource.find(model, new Query());
  for (const record of records) {
    const params = values(record);
    await db.run(insert, params);
    const actual = await db.get(select, [params[0]]);
    if (!actual) throw new Error(`Migration could not read back ${model.name}`);
    const expected = Object.fromEntries(fields.map((field, index) => [field, params[index]]));
    verify(expected, actual, fields);
  }
}

export async function up() {
  await initStore();
  await upSchema();
  const db = await getDb();
  try { await db.exec("ALTER TABLE auth_property ADD COLUMN value_type TEXT NOT NULL DEFAULT 'text'"); } catch {}
  const applied = await db.get('SELECT version FROM schema_migrations WHERE version = ?', ['002_migrate_store']);
  if (applied) return;

  await copy(db, User, 'SELECT * FROM auth_user WHERE user_id = ?', `INSERT OR REPLACE INTO auth_user (user_id, profile_id, profile, access_token, refresh_token, name, email, photo, last_seen, recovery_codes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, ['user_id', 'profile_id', 'profile', 'access_token', 'refresh_token', 'name', 'email', 'photo', 'last_seen', 'recovery_codes'], (item) => [item.userId, item.profileId, encoded(item.profile).value, item.accessToken, item.refreshToken, item.name, item.email, item.photo, item.lastSeen, encoded(item.recoveryCodes).value]);
  await copy(db, UserProperty, 'SELECT * FROM auth_property WHERE uid = ?', `INSERT OR REPLACE INTO auth_property (uid, user_id, key, value, value_type) VALUES (?, ?, ?, ?, ?)`, ['uid', 'user_id', 'key', 'value', 'value_type'], (item) => { const value = encoded(item.value); return [item.uid, item.userId, item.key, value.value, value.type]; });
  await copy(db, UserSession, 'SELECT * FROM auth_session WHERE sid = ?', `INSERT OR REPLACE INTO auth_session (sid, session) VALUES (?, ?)`, ['sid', 'session'], (item) => [item.sid, encoded(item.session).value]);
  await copy(db, Authenticator, 'SELECT * FROM auth_authenticator WHERE credential_id = ?', `INSERT OR REPLACE INTO auth_authenticator (credential_id, user_id, public_key, counter, transports, label, created_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, ['credential_id', 'user_id', 'public_key', 'counter', 'transports', 'label', 'created_at', 'last_used_at', 'revoked_at'], (item) => [item.credentialId, item.userId, item.publicKey, item.counter, encoded(item.transports).value, item.label, item.createdAt, item.lastUsedAt, item.revokedAt]);
  await copy(db, QrLoginTransaction, 'SELECT * FROM auth_qr_login WHERE token = ?', `INSERT OR REPLACE INTO auth_qr_login (token, session_id, return_url, created_at, user_id, status) VALUES (?, ?, ?, ?, ?, ?)`, ['token', 'session_id', 'return_url', 'created_at', 'user_id', 'status'], (item) => [item.token, item.sessionId, item.returnUrl, item.createdAt, item.userId, item.status]);
  await copy(db, OidcClient, 'SELECT * FROM auth_oidc_client WHERE id = ?', `INSERT OR REPLACE INTO auth_oidc_client (id, secret_hash, redirect_uris, scopes, created_at) VALUES (?, ?, ?, ?, ?)`, ['id', 'secret_hash', 'redirect_uris', 'scopes', 'created_at'], (item) => [item.id, item.secretHash, encoded(item.redirectUris).value, encoded(item.scopes).value, item.createdAt]);
  await copy(db, ApiToken, 'SELECT * FROM auth_api_token WHERE token_hash = ?', `INSERT OR REPLACE INTO auth_api_token (token_hash, user_id, client_id, scopes, label, created_at, expires_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, ['token_hash', 'user_id', 'client_id', 'scopes', 'label', 'created_at', 'expires_at', 'last_used_at', 'revoked_at'], (item) => [item.tokenHash, item.userId, item.clientId, encoded(item.scopes).value, item.label, item.createdAt, item.expiresAt, item.lastUsedAt, item.revokedAt]);
  await copy(db, AuditEvent, 'SELECT * FROM auth_audit_event WHERE id = ?', `INSERT OR REPLACE INTO auth_audit_event (id, user_id, event, app, result, timestamp, redirect_uri) VALUES (?, ?, ?, ?, ?, ?, ?)`, ['id', 'user_id', 'event', 'app', 'result', 'timestamp', 'redirect_uri'], (item) => [item.id, item.userId, item.event, item.app, item.result, item.timestamp, item.redirectUri]);
  await copy(db, SigningKey, 'SELECT * FROM auth_signing_key WHERE kid = ?', `INSERT OR REPLACE INTO auth_signing_key (kid, encrypted_private_key, public_key, status, created_at) VALUES (?, ?, ?, ?, ?)`, ['kid', 'encrypted_private_key', 'public_key', 'status', 'created_at'], (item) => [item.kid, item.encryptedPrivateKey, item.publicKey, item.status, item.createdAt]);

  await db.run('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', ['002_migrate_store', new Date().toISOString()]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
