import passport, { Profile } from 'passport';
import { randomUUID } from 'crypto';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { userAsJSON, findByProfileId, findByUserId } from './user.js';
import { User } from './store.js';

async function onUserSignIn(accessToken: string, refreshToken: string, profile: Profile, done: any) {
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
    email: profile.emails?.[0]?.value ?? '',
    photo: profile.photos?.[0]?.value ?? '',
    lastSeen: new Date().toISOString(),
  });

  await user.save();

  done(null, userAsJSON(user));
}

export const googleCallback = '/auth/google/callback';
export const githubCallback = '/auth/github/callback';

const authDomain = process.env.AUTH_DOMAIN;
const githubClientID = process.env.GITHUB_CLIENT_ID || '';
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET || '';
const githubCallbackURL = String(new URL(githubCallback, authDomain));

const googleClientID = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const googleCallbackURL = String(new URL(googleCallback, authDomain));

if (googleClientID && googleClientSecret) {
  passport.use(
    new GoogleStrategy(
      { clientID: googleClientID, clientSecret: googleClientSecret, callbackURL: googleCallbackURL },
      onUserSignIn,
    ),
  );
}

if (githubClientID && githubClientSecret) {
  passport.use(
    new GitHubStrategy(
      { clientID: githubClientID, clientSecret: githubClientSecret, callbackURL: githubCallbackURL },
      onUserSignIn,
    ),
  );
}

// See https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done: any) => {
  try {
    const user = await findByUserId(id);

    if (user) {
      return done(null, userAsJSON(user));
    }

    return done(new Error('Not found'));
  } catch (error) {
    done(new Error(String(error)));
  }
});

export default passport;
