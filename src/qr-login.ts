import QRCode from 'qrcode';
import { randomBytes } from 'crypto';
import { findByUserId, userAsJSON } from './user.js';

type Transaction = {
  sessionId: string;
  returnUrl: string;
  createdAt: number;
  userId?: string;
  status: 'pending' | 'approved' | 'denied';
};

const transactions = new Map<string, Transaction>();
const configuredLifetime = Number(process.env.QR_LOGIN_TTL_SECONDS || 300);
const lifetime = (Number.isInteger(configuredLifetime) && configuredLifetime >= 60 && configuredLifetime <= 600 ? configuredLifetime : 300) * 1000;

function clean() {
  const expiry = Date.now() - lifetime;
  for (const [token, transaction] of transactions) {
    if (transaction.createdAt < expiry) transactions.delete(token);
  }
}

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

export function createQrLogin(sessionId: string, returnUrl: string) {
  clean();
  const token = randomBytes(32).toString('base64url');
  const transaction = { sessionId, returnUrl: safeReturnUrl(returnUrl), createdAt: Date.now(), status: 'pending' as const };
  transactions.set(token, transaction);
  return { token, transaction };
}

export async function qrLoginPage(sessionId: string, returnUrl: string) {
  const { token, transaction } = createQrLogin(sessionId, returnUrl);
  const pwaUrl = new URL('/pwa/?transaction=' + encodeURIComponent(token), process.env.AUTH_DOMAIN);
  const qr = await QRCode.toDataURL(String(pwaUrl), { margin: 2, width: 320 });
  return { token, transaction, qr, pwaUrl: String(pwaUrl) };
}

function getTransaction(token: string) {
  clean();
  const transaction = transactions.get(token);
  if (!transaction || transaction.createdAt + lifetime < Date.now()) throw new Error('Invalid or expired QR login');
  return transaction;
}

export function qrLoginDetails(token: string) {
  const transaction = getTransaction(token);
  return { status: transaction.status, returnUrl: transaction.returnUrl };
}

export async function approveQrLogin(token: string, userId: string) {
  const transaction = getTransaction(token);
  if (transaction.status !== 'pending') throw new Error('QR login is no longer pending');
  transaction.userId = userId;
  transaction.status = 'approved';
}

export function denyQrLogin(token: string) {
  const transaction = getTransaction(token);
  if (transaction.status === 'pending') transaction.status = 'denied';
}

export async function completeQrLogin(token: string, sessionId: string) {
  const transaction = getTransaction(token);
  if (transaction.sessionId !== sessionId || transaction.status !== 'approved' || !transaction.userId) return null;
  const user = await findByUserId(transaction.userId);
  if (!user) return null;
  transactions.delete(token);
  return { user: userAsJSON(user), returnUrl: transaction.returnUrl };
}

export function qrLoginOrigin(token: string, sessionId: string) {
  const transaction = getTransaction(token);
  if (transaction.sessionId !== sessionId) throw new Error('QR login session mismatch');
  return transaction;
}
