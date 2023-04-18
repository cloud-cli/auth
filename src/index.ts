import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Model, Property, Resource, SQLiteDriver, Unique } from '@cloud-cli/store';

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.AUTH_CALLBACK_HOST + "/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_DOMAIN = process.env.SESSION_DOMAIN;
const PORT = Number(process.env.PORT);

@Model('auth_user')
class User extends Resource {
  @Unique() @Property(String) userId: string;
  @Property(Object) profile: any;
  @Property(String) accessToken: string;
  @Property(String) refreshToken: string;
}

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

const sessionOptions: any = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
};

if (SESSION_DOMAIN) {
  sessionOptions.cookie = {
    domain: SESSION_DOMAIN,
    httpOnly: true,
  };
}

const scopes = { 
  scope: ["profile", "email"],
  failureRedirect: "/login", 
  successRedirect: "/success",
}

const app = express();

app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());
app.get("/", passport.authenticate("google", scopes), (_req, res) => res.send('OK'));
app.get("/auth/google", passport.authenticate("google", scopes));
app.get("/auth/google/callback", passport.authenticate("google", scopes));
app.get("/login", (_req, res) => res.sendFile('../assets/login.html'));
app.get("/success", (_req, res) => res.sendFile('../assets/success.html'));

app.listen(PORT, async () => {
  Resource.use(new SQLiteDriver('/opt/data/db.sqlite'));
  await Resource.create(User);
  console.log("Auth is running on port " + PORT);
});
