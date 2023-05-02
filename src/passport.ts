import passport, { Profile } from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { User } from './user.js';
import { Query, Resource } from '@cloud-cli/store';

export const callback = '/auth/google/callback';

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
    async function verify(accessToken, refreshToken, profile, continueAuth) {
      console.log('User authenticated:', profile.id);
      const user = new User({ userId: profile.id, accessToken, refreshToken, profile });
      await user.save();

      continueAuth(null, getApiProfile(profile));
    },
  ),
);

// See https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (userId: string, done) => {
  try {
    const user = await Resource.find(User, new Query<User>().where('userId').is(userId));

    if (user.length) {
      return done(null, getApiProfile(user[0].profile));
    }

    return done(new Error('Not found'));
  } catch (error) {
    done(String(error));
  }
});

function getApiProfile(profile: Profile) {
  const { id, displayName, photos } = profile;

  return {
    id,
    displayName,
    photo: (photos.length && photos[0].value) || '',
  };
}

export default passport;
