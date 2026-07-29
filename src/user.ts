import { Query, Resource } from '@cloud-cli/store';
import { User } from './store.js';

export async function findByProfileId(profileId: string) {
  const all = await Resource.find(User, new Query<User>().where('profileId').is(String(profileId)));
  return all[0];
}

export async function findByUserId(userId: string | undefined) {
  if (!userId) return null;

  const all = await Resource.find(User, new Query<User>().where('userId').is(String(userId)));
  return all[0];
}

export function userAsJSON(user: User) {
  const { userId, name, email, photo } = user;
  return { id: userId, name, email, photo };
}
