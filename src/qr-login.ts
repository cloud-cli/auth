import QRCode from 'qrcode';
import { randomBytes } from 'crypto';
import { Query, Resource } from '@cloud-cli/store';
import { QrLoginTransaction } from './store.js';
import { findByUserId, userAsJSON } from './user.js';

const configuredLifetime = Number(process.env.QR_LOGIN_TTL_SECONDS || 300);
const lifetime = (Number.isInteger(configuredLifetime) && configuredLifetime >= 60 && configuredLifetime <= 600 ? configuredLifetime : 300) * 1000;

function safeReturnUrl(value: string) {
  if (!value) return '/';
  try {
    const url = new URL(value, process.env.AUTH_DOMAIN);
    const authOrigin = new URL(process.env.AUTH_DOMAIN || 'http://localhost').origin;
    if (url.origin !== authOrigin) return '/';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
}

export async function createQrLogin(sessionId: string, returnUrl: string) {
  const transaction = new QrLoginTransaction({
    token: randomBytes(32).toString('base64url'),
    sessionId,
    returnUrl: safeReturnUrl(returnUrl),
    createdAt: new Date().toISOString(),
    userId: '',
    status: 'pending',
  });
  await transaction.save();
  return transaction;
}

export async function qrLoginPage(sessionId: string, returnUrl: string) {
  const transaction = await createQrLogin(sessionId, returnUrl);
  const pwaUrl = new URL('/pwa/?transaction=' + encodeURIComponent(transaction.token), process.env.AUTH_DOMAIN);
  const qr = await QRCode.toDataURL(String(pwaUrl), { margin: 2, width: 320 });
  return { token: transaction.token, qr, pwaUrl: String(pwaUrl) };
}

async function getTransaction(token: string) {
  const all = await Resource.find(QrLoginTransaction, new Query<QrLoginTransaction>().where('token').is(token));
  const transaction = all[0];
  if (!transaction || Date.parse(transaction.createdAt) + lifetime < Date.now()) throw new Error('Invalid or expired QR login');
  return transaction;
}

export async function qrLoginDetails(token: string) {
  const transaction = await getTransaction(token);
  return { status: transaction.status, returnUrl: transaction.returnUrl };
}

export async function approveQrLogin(token: string, userId: string) {
  const transaction = await getTransaction(token);
  if (transaction.status !== 'pending') throw new Error('QR login is no longer pending');
  transaction.userId = userId;
  transaction.status = 'approved';
  await transaction.save();
}

export async function denyQrLogin(token: string) {
  const transaction = await getTransaction(token);
  if (transaction.status === 'pending') {
    transaction.status = 'denied';
    await transaction.save();
  }
}

export async function completeQrLogin(token: string, sessionId: string) {
  const transaction = await getTransaction(token);
  if (transaction.sessionId !== sessionId || transaction.status !== 'approved' || !transaction.userId) return null;
  const user = await findByUserId(transaction.userId);
  if (!user) return null;
  await transaction.remove();
  return { user: userAsJSON(user), returnUrl: transaction.returnUrl };
}

export async function qrLoginOrigin(token: string, sessionId: string) {
  const transaction = await getTransaction(token);
  if (transaction.sessionId !== sessionId) throw new Error('QR login session mismatch');
  return transaction;
}
