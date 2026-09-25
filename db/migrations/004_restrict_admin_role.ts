import { getDb } from '../connector.js';
import upRoles from './003_add_user_roles.js';

export async function up() {
  await upRoles();
  const db = await getDb();
  const applied = await db.get('SELECT version FROM schema_migrations WHERE version = ?', ['004_restrict_admin_role']);
  if (applied) return;

  await db.run("UPDATE auth_user SET role = 'user'");
  await db.run("UPDATE auth_user SET role = 'admin' WHERE lower(email) = lower(?)", ['homebots.inc@gmail.com']);
  await db.run('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '004_restrict_admin_role',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
