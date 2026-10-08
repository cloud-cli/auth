import { getDb } from '../connector.js';
import migrate from './006_add_oidc_logout_uris.js';

export async function up() {
  await migrate();
  const db = await getDb();
  try {
    await db.exec('ALTER TABLE auth_user ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0');
  } catch {}
  await db.exec(`CREATE TABLE IF NOT EXISTS auth_blocked_identity (
    profile_id TEXT PRIMARY KEY, blocked_at TEXT NOT NULL
  )`);
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '007_user_management',
    new Date().toISOString(),
  ]);
}

export default up;
