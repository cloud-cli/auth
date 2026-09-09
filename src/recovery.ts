import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { User } from './store.js';
import { findByEmail } from './user.js';

function normalize(code: string) {
  return code.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function hash(code: string, salt: Buffer) {
  return scryptSync(normalize(code), salt, 32).toString('base64url');
}

export function generateRecoveryCodes() {
  const codes = Array.from({ length: 10 }, () => randomBytes(5).toString('hex'));
  return {
    codes: codes.map((code) => `${code.slice(0, 5)}-${code.slice(5)}`),
    hashes: codes.map((code) => {
      const salt = randomBytes(16);
      return `${salt.toString('base64url')}:${hash(code, salt)}`;
    }),
  };
}

export async function replaceRecoveryCodes(user: User) {
  const result = generateRecoveryCodes();
  user.recoveryCodes = result.hashes;
  await user.save();
  return result.codes;
}

export async function consumeRecoveryCode(email: string, code: string) {
  const user = await findByEmail(email);
  if (!user || !Array.isArray(user.recoveryCodes)) return null;
  const normalized = normalize(code);
  const index = user.recoveryCodes.findIndex((stored) => {
    const [encodedSalt, expected] = stored.split(':');
    try {
      const actual = Buffer.from(hash(normalized, Buffer.from(encodedSalt, 'base64url')), 'base64url');
      const expectedBuffer = Buffer.from(expected, 'base64url');
      return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
    } catch {
      return false;
    }
  });
  if (index === -1) return null;

  user.recoveryCodes.splice(index, 1);
  await user.save();
  return user;
}
