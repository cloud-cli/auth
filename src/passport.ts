import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { User } from './user.js';

export const callback = "/auth/google/callback";

const clientId = process.env.GOOGLE_CLIENT_ID || '';
const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const callbackUrl = process.env.AUTH_CALLBACK_HOST + callback;

passport.use(
  new GoogleStrategy(
    {
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL: callbackUrl,
    },
    async function verify(accessToken, refreshToken, profile, cb) {
      console.log('Auth verify %s', profile);
      const userId = profile.id;
      const user = new User({ userId, accessToken, refreshToken, profile });
      await user.save();

      return cb(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  const { id, displayName } = user;
  done(null, { id, displayName });
});

passport.deserializeUser((user, done) => {
  const { id, displayName } = user;
  done(null, { id, displayName });
});


export default passport;