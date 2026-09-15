import { createCipheriv, createDecipheriv, createPublicKey, generateKeyPairSync, randomUUID } from 'crypto';
import { readFileSync } from 'fs';
import { exportJWK, importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose';
import { rows, run, SigningKey, User } from './database.js';

const issuer = (process.env.AUTH_DOMAIN || '').replace(/\/$/, '');
const privateKeyFile = process.env.JWT_PRIVATE_KEY_FILE || '';
const privateKeyPem = privateKeyFile ? readFileSync(privateKeyFile, 'utf8') : process.env.JWT_PRIVATE_KEY || '';
const encryptionKeyFile = process.env.JWT_KEY_ENCRYPTION_KEY_FILE || '';
const encryptionKey = encryptionKeyFile ? Buffer.from(readFileSync(encryptionKeyFile, 'utf8').trim(), 'hex') : null;
const keyId = process.env.JWT_KEY_ID || 'auth-1';
const ttl = Number(process.env.JWT_TTL_SECONDS || 300);
const audiences = new Set((process.env.JWT_AUDIENCES || '').split(',').map((value) => value.trim()).filter(Boolean));

let signingKey: CryptoKey | undefined;
let verificationKey: CryptoKey | undefined;
const verificationKeys = new Map<string, CryptoKey>();

if (issuer && privateKeyPem && Number.isInteger(ttl) && ttl >= 60 && ttl <= 900) {
  signingKey = await importPKCS8(privateKeyPem.replace(/\\n/g, '\n'), 'RS256');
  const publicKeyPem = createPublicKey(privateKeyPem.replace(/\\n/g, '\n')).export({ type: 'spki', format: 'pem' }).toString();
  verificationKey = await importSPKI(publicKeyPem, 'RS256');
}

export function isTokenServiceConfigured() {
  return Boolean(signingKey && verificationKey);
}

function encryptPrivateKey(value: string) {
  if (!encryptionKey || encryptionKey.length !== 32) throw new Error('JWT_KEY_ENCRYPTION_KEY_FILE is not configured');
  const iv = Buffer.from(randomUUID().replaceAll('-', '').slice(0, 24), 'hex');
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64url')).join('.');
}

function decryptPrivateKey(value: string) {
  if (!encryptionKey || encryptionKey.length !== 32) throw new Error('JWT_KEY_ENCRYPTION_KEY_FILE is not configured');
  const [encodedIv, encodedTag, encodedValue] = value.split('.');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(encodedIv, 'base64url'));
  decipher.setAuthTag(Buffer.from(encodedTag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(encodedValue, 'base64url')), decipher.final()]).toString();
}

export async function initializeSigningKeys() {
  let keys = await rows<SigningKey>('auth_signing_key');
  const now = Date.now();
  const activeKeys = keys.filter((key) => key.status === 'active').sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  if (activeKeys.length > 1) {
    for (const duplicate of activeKeys.slice(1)) {
      duplicate.status = 'retiring';
      await run('UPDATE auth_signing_key SET status = ? WHERE kid = ?', [duplicate.status, duplicate.kid]);
    }
  }
  for (const key of keys.filter((item) => item.status === 'retiring' && Date.parse(item.createdAt) + Math.max(ttl, 900) * 1000 < now)) {
    await run('DELETE FROM auth_signing_key WHERE kid = ?', [key.kid]);
  }
  keys = await rows<SigningKey>('auth_signing_key');
  if (!keys.some((key) => key.status === 'active') && keys.length) {
    const newest = keys.filter((key) => key.status !== 'revoked').sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0];
    if (newest) { newest.status = 'active'; await run('UPDATE auth_signing_key SET status = ? WHERE kid = ?', [newest.status, newest.kid]); }
  }
  if (!keys.length && privateKeyPem && encryptionKey?.length === 32) {
    const publicKey = createPublicKey(privateKeyPem.replace(/\\n/g, '\n')).export({ type: 'spki', format: 'pem' }).toString();
    await run('INSERT INTO auth_signing_key (kid, encrypted_private_key, public_key, status, created_at) VALUES (?, ?, ?, ?, ?)', [keyId, encryptPrivateKey(privateKeyPem), publicKey, 'active', new Date().toISOString()]);
  }
  const stored = await rows<SigningKey>('auth_signing_key');
  verificationKeys.clear();
  for (const key of stored.filter((item) => item.status !== 'revoked')) verificationKeys.set(key.kid, await importSPKI(key.publicKey, 'RS256'));
  const activeKey = stored.find((item) => item.status === 'active');
  if (activeKey) {
    signingKey = await importPKCS8(decryptPrivateKey(activeKey.encryptedPrivateKey), 'RS256');
    verificationKey = verificationKeys.get(activeKey.kid);
  }
}

export async function listSigningKeys() {
  const keys = await rows<SigningKey>('auth_signing_key');
  return keys.map(({ kid, status, createdAt }) => ({ kid, status, createdAt })).sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

export async function rotateSigningKey() {
  if (!encryptionKey || encryptionKey.length !== 32) throw new Error('JWT_KEY_ENCRYPTION_KEY_FILE is not configured');
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { format: 'pem', type: 'pkcs8' }, publicKeyEncoding: { format: 'pem', type: 'spki' } });
  const kid = `auth-${randomUUID()}`;
  const old = await rows<SigningKey>('auth_signing_key', 'status = ?', ['active']);
  for (const key of old) { key.status = 'retiring'; await run('UPDATE auth_signing_key SET status = ? WHERE kid = ?', [key.status, key.kid]); }
  await run('INSERT INTO auth_signing_key (kid, encrypted_private_key, public_key, status, created_at) VALUES (?, ?, ?, ?, ?)', [kid, encryptPrivateKey(pair.privateKey), pair.publicKey, 'active', new Date().toISOString()]);
  await initializeSigningKeys();
  return { kid };
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
  if (!verificationKeys.size) return null;
  const keys = await Promise.all([...verificationKeys.entries()].map(async ([kid, key]) => ({ ...(await exportJWK(key)), kid, use: 'sig', alg: 'RS256' })));
  return { keys };
}

export async function verifyAccessToken(token: string, audience: string) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  const key = verificationKeys.get(header.kid) || verificationKey;
  if (!key) throw new Error('JWT verification is not configured');
  return jwtVerify(token, key, { issuer, audience, algorithms: ['RS256'] });
}
