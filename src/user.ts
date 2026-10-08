import { Authenticator, User, rows, setPreferredUsername as persistPreferredUsername } from './database.js';

export function normalizePreferredUsername(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Username must be a string.');
  const username = value.trim().toLowerCase();
  if (!/^(?:[a-z0-9]|[a-z0-9][a-z0-9_-]{0,28}[a-z0-9])$/.test(username)) {
    throw new Error('Username must be 1–30 characters using letters, numbers, underscores, or hyphens.');
  }
  return username;
}

export async function setPreferredUsername(userId: string, value: unknown) {
  const username = normalizePreferredUsername(value);
  try {
    const result = await persistPreferredUsername(userId, username);
    if (result.changes !== 1) throw new Error('Preferred username has already been set.');
    return username;
  } catch (error) {
    if (error instanceof Error && error.message === 'Preferred username has already been set.') throw error;
    if (String(error).toLowerCase().includes('unique')) throw new Error('Username is already taken.');
    throw error;
  }
}

export async function findByProfileId(profileId: string) {
  const all = await rows<User>('auth_user', 'profile_id = ?', [String(profileId)]);
  return all[0];
}

export async function findByUserId(userId: string | undefined) {
  if (!userId) return null;

  const all = await rows<User>('auth_user', 'user_id = ?', [String(userId)]);
  return all[0];
}

export async function findByEmail(email: string) {
  const all = await rows<User>('auth_user', 'email = ?', [email]);
  return all[0];
}

export async function findAuthenticator(credentialId: string) {
  const all = await rows<Authenticator>('auth_authenticator', 'credential_id = ?', [credentialId]);
  return all[0];
}

export async function findAuthenticatorsByUserId(userId: string) {
  return rows<Authenticator>('auth_authenticator', 'user_id = ?', [userId]);
}

export function userAsJSON(user: User) {
  const { userId, name, email, photo, role, preferredUsername } = user;
  return { id: userId, name, email, photo, role, preferred_username: preferredUsername || null };
}
