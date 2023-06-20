import { Model, Primary, Property, Resource, SQLiteDriver, Unique } from '@cloud-cli/store';

const dbPath = process.env.DB_PATH;

@Model('auth_user')
export class User extends Resource {
  @Unique() @Property(String) userId: string;
  @Property(Object) profile: any;
  @Property(String) accessToken: string;
  @Property(String) refreshToken: string;
}

@Model('auth_property')
export class UserProperty extends Resource {
  @Primary() @Property(Number) uid: number;
  @Unique() @Property(String) userId: string;
  @Property(String) key: string;
  @Property(String) value: string;
}

export async function initUser() {
  Resource.use(new SQLiteDriver(dbPath));
  await Resource.create(User);
  await Resource.create(UserProperty);
}