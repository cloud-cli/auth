import passport, { Profile } from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { User, UserProperty } from "./user.js";
import { Query, Resource } from "@cloud-cli/store";
import { randomUUID } from "crypto";
import { findByProfileId } from "./user.js";

export const callback = "/auth/google/callback";

const clientID = process.env.GOOGLE_CLIENT_ID || "";
const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";
const callbackURL = String(new URL(callback, process.env.AUTH_DOMAIN));

passport.use(
  new GoogleStrategy(
    { clientID, clientSecret, callbackURL },
    async function verify(
      accessToken: string,
      refreshToken: string,
      profile: Profile,
      done: any
    ) {
      console.log("User authenticated:", profile.id);
      let user = await findByProfileId(profile.id);

      if (!user) {
        user = new User({
          userId: randomUUID(),
        });
      }

      Object.assign(user, {
        accessToken,
        refreshToken,
        profileId: profile.id,
        name: profile.displayName,
        email: profile.emails[0]?.value ?? "",
        photo: profile.photos[0]?.value ?? "",
      });

      await user.save();

      done(null, user);
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
      return done(null, user[0]);
    }

    return done(new Error("Not found"));
  } catch (error) {
    done(String(error));
  }
});

export default passport;
