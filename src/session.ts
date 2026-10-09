import session from 'express-session';
import sessionStore from './session-store.js';
import express from 'express';

const {
  SESSION_SECRET = '',
  SESSION_DOMAIN = '',
  SESSION_COOKIE_SAMESITE = '',
  SESSION_COOKIE_SECURE = '',
} = process.env;

const cookieOptions: session.CookieOptions = {
  path: '/',
  httpOnly: true,
};

if (SESSION_DOMAIN) {
  cookieOptions.domain = SESSION_DOMAIN;
}

if (SESSION_COOKIE_SAMESITE) {
  cookieOptions.sameSite = SESSION_COOKIE_SAMESITE as session.CookieOptions['sameSite'];
} else if (SESSION_DOMAIN) {
  cookieOptions.sameSite = false;
}

if (SESSION_COOKIE_SECURE) {
  cookieOptions.secure = true;
}

const sessionOptions: session.SessionOptions = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: cookieOptions,
};

export function normalizeSessionCookieHeader(cookieHeader = '') {
  const cookies = cookieHeader.split(';');
  const sessionCookieIndexes = cookies.reduce<number[]>((indexes, cookie, index) => {
    if (cookie.trim().startsWith('connect.sid=')) {
      indexes.push(index);
    }
    return indexes;
  }, []);

  if (sessionCookieIndexes.length <= 1) {
    return { cookieHeader, duplicateCount: 0 };
  }

  const selectedIndex = sessionCookieIndexes[sessionCookieIndexes.length - 1];
  const duplicateCount = sessionCookieIndexes.length;
  const normalizedCookieHeader = cookies
    .filter((cookie, index) => !cookie.trim().startsWith('connect.sid=') || index === selectedIndex)
    .join('; ');

  return { cookieHeader: normalizedCookieHeader, duplicateCount };
}

export default session(sessionOptions) as express.RequestHandler;
