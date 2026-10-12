import { getDb } from '../connector.js';
import migrate from './007_user_management.js';

export async function up() {
  await migrate();
  const db = await getDb();
  await db.exec(`CREATE TABLE IF NOT EXISTS auth_oidc_refresh_token (
    family_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    previous_hashes TEXT NOT NULL DEFAULT '[]',
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_oidc_refresh_client ON auth_oidc_refresh_token(client_id);
  CREATE INDEX IF NOT EXISTS idx_oidc_refresh_user ON auth_oidc_refresh_token(user_id);`);
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '008_oidc_refresh_tokens',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
