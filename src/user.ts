import { Query, Resource } from '@cloud-cli/store';
import { Authenticator, User } from './store.js';

export async function findByProfileId(profileId: string) {
  const all = await Resource.find(User, new Query<User>().where('profileId').is(String(profileId)));
  return all[0];
}

export async function findByUserId(userId: string | undefined) {
  if (!userId) return null;

  const all = await Resource.find(User, new Query<User>().where('userId').is(String(userId)));
  return all[0];
}

export async function findByEmail(email: string) {
  const all = await Resource.find(User, new Query<User>().where('email').is(email));
  return all[0];
}

export async function findAuthenticator(credentialId: string) {
  const all = await Resource.find(Authenticator, new Query<Authenticator>().where('credentialId').is(credentialId));
  return all[0];
}

export async function findAuthenticatorsByUserId(userId: string) {
  return Resource.find(Authenticator, new Query<Authenticator>().where('userId').is(userId));
}

export function userAsJSON(user: User) {
  const { userId, name, email, photo } = user;
  return { id: userId, name, email, photo };
}
