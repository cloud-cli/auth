import { Authenticator, User, rows } from './database.js';

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
  const { userId, name, email, photo } = user;
  return { id: userId, name, email, photo };
}
