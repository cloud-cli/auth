import { createPublicKey, randomUUID } from 'crypto';
import { exportJWK, importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose';
import { User } from './store.js';

const issuer = (process.env.AUTH_DOMAIN || '').replace(/\/$/, '');
const privateKeyPem = process.env.JWT_PRIVATE_KEY || '';
const keyId = process.env.JWT_KEY_ID || 'auth-1';
const ttl = Number(process.env.JWT_TTL_SECONDS || 300);
const audiences = new Set((process.env.JWT_AUDIENCES || '').split(',').map((value) => value.trim()).filter(Boolean));

let signingKey: CryptoKey | undefined;
let verificationKey: CryptoKey | undefined;

if (issuer && privateKeyPem && Number.isInteger(ttl) && ttl >= 60 && ttl <= 900) {
  signingKey = await importPKCS8(privateKeyPem.replace(/\\n/g, '\n'), 'RS256');
  const publicKeyPem = createPublicKey(privateKeyPem.replace(/\\n/g, '\n')).export({ type: 'spki', format: 'pem' }).toString();
  verificationKey = await importSPKI(publicKeyPem, 'RS256');
}

export function isTokenServiceConfigured() {
  return Boolean(signingKey && verificationKey);
}

export function isAllowedAudience(audience: string) {
  return audiences.has(audience);
}

export function accessTokenTtl() {
  return ttl;
}

export async function createAccessToken(userId: string, audience: string) {
  if (!signingKey) throw new Error('JWT signing is not configured');

  return new SignJWT()
    .setProtectedHeader({ alg: 'RS256', kid: keyId, typ: 'JWT' })
    .setSubject(userId)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(randomUUID())
    .sign(signingKey);
}

export async function createIdentityToken(user: User, audience: string) {
  if (!signingKey) throw new Error('JWT signing is not configured');

  return new SignJWT({ name: user.name, email: user.email, picture: user.photo })
    .setProtectedHeader({ alg: 'RS256', kid: keyId, typ: 'JWT' })
    .setSubject(user.userId)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(randomUUID())
    .sign(signingKey);
}

export async function getJwks() {
  if (!verificationKey) return null;

  const key = await exportJWK(verificationKey);
  return { keys: [{ ...key, kid: keyId, use: 'sig', alg: 'RS256' }] };
}

export async function verifyAccessToken(token: string, audience: string) {
  if (!verificationKey) throw new Error('JWT verification is not configured');

  return jwtVerify(token, verificationKey, { issuer, audience, algorithms: ['RS256'] });
}
