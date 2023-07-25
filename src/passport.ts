import passport, { Profile } from "passport";
import { randomUUID } from "crypto";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Query, Resource } from "@cloud-cli/store";
import { User, toJSON, findByProfileId } from "./user.js";

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
          profileId: profile.id,
        });
      }

      Object.assign(user, {
        accessToken,
        refreshToken,
        name: profile.displayName,
        email: profile.emails[0]?.value ?? "",
        photo: profile.photos[0]?.value ?? "",
        lastSeen: new Date().toISOString(),
      });

      await user.save();

      done(null, toJSON(user));
    }
  )
);

// See https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done: any) => {
  try {
    const users = await Resource.find(
      User,
      new Query<User>().where("userId").is(String(id))
    );

    if (users.length) {
      return done(null, toJSON(users[0]));
    }

    return done(new Error("Not found"));
  } catch (error) {
    console.log("deserialize", error);
    done(new Error(String(error)));
  }
});

export default passport;
