import { getDb } from '../connector.js';
import upRoles from './003_add_user_roles.js';

export async function up() {
  await upRoles();
  const db = await getDb();
  try {
    await db.exec('ALTER TABLE auth_user ADD COLUMN preferred_username TEXT');
  } catch {}
  await db.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_user_preferred_username ON auth_user(preferred_username COLLATE NOCASE) WHERE preferred_username IS NOT NULL AND preferred_username != ''",
  );
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '004_add_preferred_username',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
