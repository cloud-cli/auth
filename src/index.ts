import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Model, Property, Resource, SQLiteDriver, Unique } from '@cloud-cli/store';

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.AUTH_CALLBACK_HOST + "/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET;
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
    async function (accessToken, refreshToken, profile, cb) {
      console.log(accessToken, refreshToken, profile);
      const userId = profile.id;
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

const app = express();

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (_req, res) {
    res.redirect("/success");
  }
);

app.get("/login", (_req, res) => {
  res.send(
    `<h1>Login</h1>
    <a href="/auth/google" onclick="s(this)">Sign in with Google</a>
    <script>function s() {sessionStorage.url=[...new URLSearchParams(location.search)].find(p=>p[0]==="url")?.[1]}</script>`
  );
});

app.get("/success", (_req, res) => {
  res.send(
    '<h1>You are authenticated!</h1><a href="#" onclick="sessionStorage.url&&window.location=sessionStorage.url">Continue</a>'
  );
});

app.listen(PORT, async () => {
  Resource.use(new SQLiteDriver('/opt/data/db.sqlite'));
  await Resource.create(User);
  console.log("App is listening on port " + PORT);
});
