import {
  Model,
  Primary,
  Property,
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

@Model("auth_session")
export class UserSession extends Resource {
  @Primary() @Property(String) sid: string;
  @Property(Object) session: any;
}

export async function initStore() {
  Resource.use(new StoreDriver());
  await Resource.create(User);
  await Resource.create(UserProperty);
  await Resource.create(UserSession);
}
