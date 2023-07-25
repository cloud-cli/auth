import log from './log.js';
import {
  Model,
  Primary,
  Property,
  Query,
  Resource,
  StoreDriver,
} from "@cloud-cli/store";

@Model("auth_user")
export class User extends Resource {
  @Primary() @Property(String) userId: string;
  @Property(String) profileId: string;
  @Property(Object) profile: any;
  @Property(String) accessToken: string;
  @Property(String) refreshToken: string;
  @Property(String) name: string;
  @Property(String) email: string;
  @Property(String) photo: string;
  @Property(String) lastSeen: string;
}

@Model("auth_property")
export class UserProperty extends Resource {
  @Primary() @Property(String) uid: string;
  @Property(String) userId: string;
  @Property(String) key: string;
  @Property(String) value: string;
}

export async function initUser() {
  Resource.use(new StoreDriver());
  await Resource.create(User);
  await Resource.create(UserProperty);
}

export async function findByProfileId(profileId: string) {
  log('findByProfileId', profileId);
  const all = await Resource.find(
    User,
    new Query<User>().where("profileId").is(String(profileId))
  );
  return all[0];
}

export async function findByUserId(userId: string) {
  log('findByUserId', userId);
  const all = await Resource.find(
    User,
    new Query<User>().where("userId").is(String(userId))
  );
  return all[0];
}

export function toJSON(user: User) {
  const { userId, name, email, photo } = user;
  return { id: userId, name, email, photo };
}
