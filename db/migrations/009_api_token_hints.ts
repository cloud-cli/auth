import { getDb } from '../connector.js';
import migrate from './008_oidc_refresh_tokens.js';

export async function up() {
  await migrate();
  const db = await getDb();
  try {
    await db.exec("ALTER TABLE auth_api_token ADD COLUMN token_hint TEXT NOT NULL DEFAULT ''");
  } catch {}
  await db.run('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)', [
    '009_api_token_hints',
    new Date().toISOString(),
  ]);
}

export default up;

if (import.meta.url === `file://${process.argv[1]}`) await up();
