import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const defaultIssuer = '__API_URL__';

function decodeBase64Url(value) {
  return Buffer.from(value, 'base64url');
}

function parseToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT');

  try {
    return {
      header: JSON.parse(decodeBase64Url(parts[0]).toString('utf8')),
      payload: JSON.parse(decodeBase64Url(parts[1]).toString('utf8')),
      signature: decodeBase64Url(parts[2]),
      signed: Buffer.from(`${parts[0]}.${parts[1]}`),
    };
  } catch {
    throw new Error('Invalid JWT');
  }
}

export function getCookies(request) {
  const header = request.headers?.get ? request.headers.get('cookie') : request.headers?.cookie;
  if (!header) return {};

  return Object.fromEntries(header.split(';').map((part) => {
    const separator = part.indexOf('=');
    if (separator === -1) return [part.trim(), ''];
    return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
  }));
}

export function getSessionCookie(request, cookieName = 'connect.sid') {
  const value = getCookies(request)[cookieName];
  return value ? `${cookieName}=${encodeURIComponent(value)}` : '';
}

export function createAuthClient({ issuer = defaultIssuer, clientId, sessionCookieName = 'connect.sid' } = {}) {
  if (!clientId) throw new Error('A client ID is required');

  let jwks;
  let jwksExpiresAt = 0;

  async function getJwks() {
    if (jwks && Date.now() < jwksExpiresAt) return jwks;

    const response = await fetch(new URL('/.well-known/jwks.json', issuer));
    if (!response.ok) throw new Error(`Could not load JWKS: ${response.status}`);

    jwks = await response.json();
    jwksExpiresAt = Date.now() + 60 * 60 * 1000;
    return jwks;
  }

  async function verifyToken(token) {
    const { header, payload, signature, signed } = parseToken(token);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Unsupported JWT');

    const keys = await getJwks();
    const jwk = keys.keys?.find((key) => key.kid === header.kid && key.kty === 'RSA');
    if (!jwk) throw new Error('Unknown JWT signing key');

    const key = createPublicKey({ key: jwk, format: 'jwk' });
    if (!verify('RSA-SHA256', signed, key, signature)) throw new Error('Invalid JWT signature');

    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== issuer || !audiences.includes(clientId) || typeof payload.sub !== 'string') throw new Error('Invalid JWT claims');
    if (typeof payload.exp !== 'number' || payload.exp <= now) throw new Error('Expired JWT');
    if (typeof payload.nbf === 'number' && payload.nbf > now) throw new Error('JWT is not active');

    return payload;
  }

  async function getProfile(token) {
    await verifyToken(token);
    const response = await fetch(new URL('/userinfo', issuer), {
      headers: { Authorization: `Bearer ${token}`, 'X-Auth-Audience': clientId },
    });
    if (!response.ok) throw new Error(`Could not load profile: ${response.status}`);

    return response.json();
  }

  async function getSessionProfile(request) {
    const cookie = getSessionCookie(request, sessionCookieName);
    if (!cookie) return null;

    const response = await fetch(new URL('/profile', issuer), { headers: { Cookie: cookie } });
    return response.ok ? response.json() : null;
  }

  async function isSessionAuthenticated(request) {
    return Boolean(await getSessionProfile(request));
  }

  async function requireSession(request, response) {
    const profile = await getSessionProfile(request);
    if (profile) return profile;

    response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Authentication required');
    return null;
  }

  function createAuthorizationRequest({ redirectUri }) {
    if (!redirectUri) throw new Error('A redirect URI is required');

    const state = randomBytes(32).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const url = new URL('/authorize', issuer);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', createHash('sha256').update(codeVerifier).digest('base64url'));
    url.searchParams.set('code_challenge_method', 'S256');
    return { url: String(url), state, codeVerifier };
  }

  async function exchangeCode({ code, codeVerifier, redirectUri, clientSecret }) {
    const body = new URLSearchParams({ grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, code_verifier: codeVerifier });
    const response = await fetch(new URL('/token', issuer), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    if (!response.ok) throw new Error(`Could not exchange authorization code: ${response.status}`);
    return response.json();
  }

  return { createAuthorizationRequest, exchangeCode, verifyToken, getProfile, getSessionProfile, isSessionAuthenticated, requireSession };
}
