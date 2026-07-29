import { Query, Resource } from '@cloud-cli/store';
import { UserProperty } from './store.js';

export async function setProperty(userId: string | undefined, key: string, value: string) {
  if (!userId) return;

  const found = await Resource.find(
    UserProperty,
    new Query<UserProperty>().where('userId').is(userId).where('key').is(key),
  );

  if (found.length) {
    const property = found[0];
    property.value = value;
    await property.save();
    return property;
  }

  const propertyId = await new UserProperty({
    userId,
    key,
    value,
  }).save();

  return await new UserProperty({ uid: propertyId }).find();
}

export async function getProperties(userId?: string, key?: string) {
  if (!userId) return [];

  const query = new Query<UserProperty>().where('userId').is(userId);
  if (key) {
    query.where('key').is(key);
  }

  const entries = await Resource.find(UserProperty, query);
  const properties = entries.map((p) => ({
    key: p.key,
    value: p.value,
  }));

  return properties;
}

export async function removeProperty(userId: string | undefined, key: string) {
  if (!userId) return;

  const entries = await Resource.find(
    UserProperty,
    new Query<UserProperty>().where('key').is(key).where('userId').is(userId),
  );

  for (const p of entries) {
    await p.remove();
  }
}

export async function getProperty(userId: string | undefined, key: string) {
  if (!userId) return null;
  const p = await getProperties(userId, key);
  return p.length ? p[0] : null;
}
