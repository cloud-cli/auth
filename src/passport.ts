import passport, { Profile } from 'passport';
import { randomUUID } from 'crypto';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { userAsJSON, findByProfileId, findByUserId, isUserSuspended } from './user.js';
import { all, saveUser } from './database.js';
import { recordAudit } from './audit.js';

async function onUserSignIn(accessToken: string, refreshToken: string, profile: Profile, done: any) {
  let user = await findByProfileId(profile.id);

  const blocked = await all('SELECT profile_id FROM auth_blocked_identity WHERE profile_id = ?', [profile.id]);
  if (blocked.length) return done(null, false, { message: 'This identity is blocked.' });
  if (user?.disabled) return done(null, false, { message: 'This account is disabled.' });

  if (!user) {
    user = {
      userId: randomUUID(),
      profileId: profile.id,
      accessToken: '',
      refreshToken: '',
      name: '',
      email: '',
      photo: '',
      lastSeen: '',
      role: 'user',
    };
  }

  Object.assign(user, {
    accessToken,
    refreshToken,
    name: profile.displayName,
    email: profile.emails?.[0]?.value ?? '',
    photo: profile.photos?.[0]?.value ?? '',
    lastSeen: new Date().toISOString(),
  });

  await saveUser(user);
  await recordAudit({ userId: user.userId, event: 'google-authentication', app: 'Google', result: 'success' });

  done(null, userAsJSON(user));
}

export const googleCallback = '/auth/google/callback';

const authDomain = process.env.AUTH_DOMAIN;
const googleClientID = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const googleCallbackURL = String(new URL(googleCallback, authDomain));

if (googleClientID && googleClientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: googleClientID,
        clientSecret: googleClientSecret,
        callbackURL: googleCallbackURL,
      },
      onUserSignIn,
    ),
  );
}

// See https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done: any) => {
  try {
    const user = await findByUserId(id);
    if (!user) {
      console.warn('Passport session restore failed: account not found');
      return done(new Error('Not found'));
    }

    if (await isUserSuspended(user.userId)) {
      console.warn('Passport session restore failed: account unavailable');
      return done(new Error('Not found'));
    }

    return done(null, userAsJSON(user));
  } catch (error) {
    console.error('Passport session restore failed', {
      errorName: error instanceof Error ? error.name : 'UnknownError',
    });
    done(new Error(String(error)));
  }
});

export default passport;
