import { getDb } from '../connector.js';
import migrate from './009_api_token_hints.js';

export async function up() {
  await migrate();
  const db = await getDb();
  await db.exec(`
    CREATE TABLE IF NOT EXISTS auth_agent (
      user_id TEXT PRIMARY KEY,
      created_by_user_id TEXT NOT NULL,
      root_owner_user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_auth_agent_creator ON auth_agent(created_by_user_id);
    CREATE INDEX IF NOT EXISTS idx_auth_agent_root_owner ON auth_agent(root_owner_user_id);
    CREATE TABLE IF NOT EXISTS auth_agent_token (
      token_hash TEXT PRIMARY KEY,
      token_hint TEXT NOT NULL,
      user_id TEXT NOT NULL,
      label TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT '',
      revoked_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_auth_agent_token_user ON auth_agent_token(user_id);
  `);
  try {
    await db.exec("ALTER TABLE auth_oidc_client ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT ''");
  } catch {}
  try {
    await db.exec('ALTER TABLE auth_oidc_client ADD COLUMN available_to_users INTEGER NOT NULL DEFAULT 1');
  } catch {}
  try {
    await db.exec("ALTER TABLE auth_oidc_client ADD COLUMN display_name TEXT NOT NULL DEFAULT ''");
  } catch {}
  await db.exec('CREATE INDEX IF NOT EXISTS idx_auth_oidc_client_owner ON auth_oidc_client(owner_user_id)');
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '010_agents',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
