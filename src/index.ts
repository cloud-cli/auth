import express from 'express';
import { readFileSync } from 'fs';
import { initUser } from './user.js';
import session from './session.js';
import passport, { callback } from './passport.js';

const PORT = Number(process.env.PORT);
const loginPage = readFileSync('./assets/login.html', 'utf8');
const successPage = readFileSync('./assets/success.html', 'utf8');

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).send(loginPage);
  }

  next();
}

const scopes = {
  scope: ['profile', 'email'],
  failureRedirect: '/login',
  successRedirect: '/success',
};

const app = express();

app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.head('/', protectedRoute, (_req, res) => res.status(200).send(''));
app.get('/', protectedRoute, (_req, res) => res.status(200).send('OK'));
app.delete('/', protectedRoute, (req, res, next) =>
  req.logout((err) => (err ? next(err) : res.status(202).send('OK'))),
);

app.get('/profile', protectedRoute, (req, res) => res.send(req.user));
app.get('/auth/google', passport.authenticate('google', scopes));
app.get(callback, passport.authenticate('google', scopes));

app.get('/login', (_, res) => res.send(loginPage));
app.get('/success', (_, res) => res.send(successPage));

app.listen(PORT, async () => {
  await initUser();
  console.log('Auth is running on port ' + PORT);
});
