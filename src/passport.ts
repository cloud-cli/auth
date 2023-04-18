import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const CALLBACK_URL = process.env.AUTH_CALLBACK_HOST + "/auth/google/callback";

passport.use(
  new GoogleStrategy(
    {
      clientID: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      callbackURL: CALLBACK_URL,
    },
    async function verify(accessToken, refreshToken, profile, cb) {
      const userId = profile.id;
      console.log('Auth verify %s', profile.id);
      const user = new User({ userId, accessToken, refreshToken, profile });
      await user.save();

      return cb(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  console.log("s", user);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log("d", user);
  done(null, user);
});


export default passport;