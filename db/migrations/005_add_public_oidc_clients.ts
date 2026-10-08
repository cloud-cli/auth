import { getDb } from '../connector.js';
import upPreferredUsername from './004_add_preferred_username.js';

export async function up() {
  await upPreferredUsername();
  const db = await getDb();
  try {
    await db.exec('ALTER TABLE auth_oidc_client ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0');
  } catch {}
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '005_add_public_oidc_clients',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
