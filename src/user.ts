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
  @Property(Object) profile: any;
  @Property(String) accessToken: string;
  @Property(String) refreshToken: string;
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
