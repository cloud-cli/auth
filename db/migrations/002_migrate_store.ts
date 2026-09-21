import { getDb } from '../connector.js';
import upSchema from './001_create-db.js';

export async function up() {
  await upSchema();
  const db = await getDb();
  try {
    await db.exec("ALTER TABLE auth_property ADD COLUMN value_type TEXT NOT NULL DEFAULT 'text'");
  } catch {}
  const applied = await db.get('SELECT version FROM schema_migrations WHERE version = ?', ['002_migrate_store']);
  if (applied) return;

  await db.run('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '002_migrate_store',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
