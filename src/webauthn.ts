import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { Authenticator } from './store.js';
import { findAuthenticator, findAuthenticatorsByUserId, findByUserId } from './user.js';

const rpID = new URL(process.env.AUTH_DOMAIN || 'http://localhost').hostname;
const origin = (process.env.AUTH_DOMAIN || '').replace(/\/$/, '');
const rpName = process.env.AUTH_NAME || 'Auth';
const challenges = new Map<string, { type: 'registration' | 'authentication'; userId?: string; expiresAt: number }>();

function cleanChallenges() {
  const now = Date.now();
  for (const [challenge, value] of challenges) if (value.expiresAt < now) challenges.delete(challenge);
}

function saveChallenge(challenge: string, type: 'registration' | 'authentication', userId?: string) {
  cleanChallenges();
  challenges.set(challenge, { type, userId, expiresAt: Date.now() + 120_000 });
}

function takeChallenge(challenge: string, type: 'registration' | 'authentication') {
  const saved = challenges.get(challenge);
  challenges.delete(challenge);
  if (!saved || saved.type !== type || saved.expiresAt < Date.now()) throw new Error('Invalid or expired WebAuthn challenge');
  return { ...saved, challenge };
}

export async function registrationOptions(userId: string) {
  const user = await findByUserId(userId);
  if (!user) throw new Error('User not found');
  const authenticators = await findAuthenticatorsByUserId(userId);
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.email || user.userId,
    userDisplayName: user.name || user.email || user.userId,
    userID: Buffer.from(user.userId),
    attestationType: 'none',
    excludeCredentials: authenticators.filter((item) => !item.revokedAt).map((item) => ({ id: item.credentialId, transports: item.transports })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });
  saveChallenge(options.challenge, 'registration', userId);
  return options;
}

export async function registerAuthenticator(userId: string, response: any, label: string) {
  const challenge = takeChallenge(response.response?.clientDataJSON ? JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString()).challenge : '', 'registration');
  if (challenge.userId !== userId) throw new Error('Challenge user mismatch');
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });
  if (!verification.verified || !verification.registrationInfo) throw new Error('WebAuthn registration failed');

  const { credential } = verification.registrationInfo;
  const authenticator = new Authenticator({
    credentialId: credential.id,
    userId,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: response.transports || [],
    label: label || 'Passkey',
    createdAt: new Date().toISOString(),
    lastUsedAt: '',
    revokedAt: '',
  });
  await authenticator.save();
  return authenticator;
}

export async function authenticationOptions(userId?: string) {
  const authenticators = userId ? await findAuthenticatorsByUserId(userId) : [];
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials: authenticators.filter((item) => !item.revokedAt).map((item) => ({ id: item.credentialId, transports: item.transports })),
  });
  saveChallenge(options.challenge, 'authentication');
  return options;
}

export async function authenticate(response: any) {
  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString());
  const challenge = takeChallenge(clientData.challenge, 'authentication');
  const authenticator = await findAuthenticator(response.id);
  if (!authenticator || authenticator.revokedAt) throw new Error('Unknown or revoked authenticator');

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: authenticator.credentialId,
      publicKey: Buffer.from(authenticator.publicKey, 'base64url'),
      counter: authenticator.counter,
      transports: authenticator.transports,
    },
  });
  if (!verification.verified) throw new Error('WebAuthn authentication failed');

  authenticator.counter = verification.authenticationInfo.newCounter;
  authenticator.lastUsedAt = new Date().toISOString();
  await authenticator.save();
  return { userId: authenticator.userId, challenge: challenge.challenge };
}

export async function listAuthenticators(userId: string) {
  return findAuthenticatorsByUserId(userId);
}

export async function revokeAuthenticator(userId: string, credentialId: string) {
  const authenticator = await findAuthenticator(credentialId);
  if (!authenticator || authenticator.userId !== userId) return false;
  authenticator.revokedAt = new Date().toISOString();
  await authenticator.save();
  return true;
}
