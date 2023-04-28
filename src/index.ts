import express from "express";
import { readFileSync } from 'fs';
import { initUser } from './user.js';
import session from './session.js';
import passport from './passport.js';

const PORT = Number(process.env.PORT);
const loginPage = readFileSync('./assets/login.html', 'utf8');
const successPage = readFileSync('./assets/success.html', 'utf8');

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.send(401, loginPage);
  }

  next();
}

const scopes = {
  scope: ["profile", "email"],
  failureRedirect: "/login",
  successRedirect: "/success",
};

const app = express();

app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", protectedRoute, (req, res) => { const { id, displayName } = req.user; res.send({ id, displayName }) });
app.get("/auth/google", passport.authenticate("google", scopes));
app.get(passport.callback, passport.authenticate("google", scopes));
app.get("/login", (_, res) => res.send(loginPage));
app.get("/success", (_, res) => res.send(successPage));

app.listen(PORT, async () => {
  await initUser();
  console.log("Auth is running on port " + PORT);
});
