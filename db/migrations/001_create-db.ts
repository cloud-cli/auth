import { getDb } from '../connector.js';

const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_user (
  user_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  profile TEXT,
  access_token TEXT,
  refresh_token TEXT,
  name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  photo TEXT NOT NULL DEFAULT '',
  last_seen TEXT NOT NULL DEFAULT '',
  recovery_codes TEXT
);

CREATE TABLE IF NOT EXISTS auth_property (
  uid TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL DEFAULT '',
  value_type TEXT NOT NULL DEFAULT 'text',
  UNIQUE (user_id, key)
);

CREATE TABLE IF NOT EXISTS auth_session (
  sid TEXT PRIMARY KEY,
  session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_authenticator (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_qr_login (
  token TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  return_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_oidc_client (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_api_token (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_audit_event (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  event TEXT NOT NULL,
  app TEXT NOT NULL,
  result TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  redirect_uri TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_signing_key (
  kid TEXT PRIMARY KEY,
  encrypted_private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_property_user ON auth_property(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_authenticator_user ON auth_authenticator(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_api_token_user_client ON auth_api_token(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_user_time ON auth_audit_event(user_id, timestamp);
`;

export async function up() {
  const db = await getDb();
  await db.exec(schema);
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', ['001_create-db', new Date().toISOString()]);
}

export default up;
