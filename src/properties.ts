import { randomUUID } from 'crypto';
import { UserProperty, rows, run } from './database.js';

export async function setProperty(userId: string | undefined, key: string, value: string) {
  if (!userId) return;

  const found = await rows<UserProperty>('auth_property', 'user_id = ? AND key = ?', [userId, key]);

  if (found.length) {
    const property = found[0];
    property.value = value;
    await run('UPDATE auth_property SET value = ?, value_type = ? WHERE uid = ?', [String(value), 'text', property.uid]);
    return property;
  }

  const uid = randomUUID();
  await run('INSERT INTO auth_property (uid, user_id, key, value, value_type) VALUES (?, ?, ?, ?, ?)', [uid, userId, key, String(value), 'text']);
  return (await rows<UserProperty>('auth_property', 'uid = ?', [uid]))[0];
}

export async function getProperties(userId?: string, key?: string) {
  if (!userId) return [];

  const entries = await rows<UserProperty>('auth_property', key ? 'user_id = ? AND key = ?' : 'user_id = ?', key ? [userId, key] : [userId]);
  const properties = entries.map((p) => ({
    key: p.key,
    value: p.value,
  }));

  return properties;
}

export async function removeProperty(userId: string | undefined, key: string) {
  if (!userId) return;

  const entries = await rows<UserProperty>('auth_property', 'key = ? AND user_id = ?', [key, userId]);

  for (const p of entries) {
    await run('DELETE FROM auth_property WHERE uid = ?', [p.uid]);
  }
}

export async function getProperty(userId: string | undefined, key: string) {
  if (!userId) return null;
  const p = await getProperties(userId, key);
  return p.length ? p[0] : null;
}
