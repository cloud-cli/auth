import { getDb } from '../connector.js';
import upStore from './002_migrate_store.js';

export async function up() {
  await upStore();
  const db = await getDb();
  try {
    await db.exec("ALTER TABLE auth_user ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
  } catch {}
  const applied = await db.get('SELECT version FROM schema_migrations WHERE version = ?', ['003_add_user_roles']);
  if (applied) return;

  await db.run("UPDATE auth_user SET role = 'admin'");
  await db.run('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '003_add_user_roles',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
