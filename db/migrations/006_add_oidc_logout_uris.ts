import { getDb } from '../connector.js';
import upPublicClients from './005_add_public_oidc_clients.js';

export async function up() {
  await upPublicClients();
  const db = await getDb();
  try {
    await db.exec("ALTER TABLE auth_oidc_client ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]'");
  } catch {}
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '006_add_oidc_logout_uris',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
