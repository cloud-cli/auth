import passport, { Profile } from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { User, UserProperty } from "./user.js";
import { Query, Resource } from "@cloud-cli/store";
import { randomUUID } from 'crypto';

export const callback = "/auth/google/callback";

const clientID = process.env.GOOGLE_CLIENT_ID || "";
const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";
const callbackURL = String(new URL(callback, process.env.AUTH_DOMAIN));

passport.use(
  new GoogleStrategy(
    { clientID, clientSecret, callbackURL },
    async function verify(accessToken, refreshToken, profile, continueAuth) {
      console.log("User authenticated:", profile.id);
      const user = new User({
        userId: randomUUID(),
        accessToken,
        refreshToken,
        profileId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        photo: profile.photos[0].value,
      });

      await user.save();

      continueAuth(null, await getApiProfile(profile));
    }
  )
);

// See https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (profileId: string, done) => {
  try {
    const user = await Resource.find(
      User,
      new Query<User>().where("profileId").is(profileId)
    );

    if (user.length) {
      return done(null, await getApiProfile(user[0].profile));
    }

    return done(new Error("Not found"));
  } catch (error) {
    done(String(error));
  }
});

async function getApiProfile(profile: Profile) {
  const { id, displayName, photos } = profile;
  const properties = await Resource.find(
    UserProperty,
    new Query<UserProperty>().where("userId").is(id)
  );

  return {
    id,
    displayName,
    photo: (photos.length && photos[0].value) || "",
    properties: properties.map((p) => ({ key: p.key, value: p.value })),
  };
}

export default passport;
