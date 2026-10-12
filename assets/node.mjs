import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const defaultIssuer = '__API_URL__';
const decodeBase64Url = (value) => Buffer.from(value, 'base64url');

function parseToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT');
  }
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

class AuthApiError extends Error {
  constructor(method, path, status, detail) {
    super(`Auth request ${method} ${path} failed: ${status} ${detail}`);
    this.name = 'AuthApiError';
    this.status = status;
  }
}

export function getCookies(request) {
  const header = request?.headers?.get ? request.headers.get('cookie') : request?.headers?.cookie;
  if (!header) {
    return {};
  }
  return Object.fromEntries(
    header.split(';').map((part) => {
      const separator = part.indexOf('=');
      if (separator === -1) {
        return [part.trim(), ''];
      }
      const value = part.slice(separator + 1).trim();
      try {
        return [part.slice(0, separator).trim(), decodeURIComponent(value)];
      } catch {
        return [part.slice(0, separator).trim(), value];
      }
    }),
  );
}

export function getSessionCookie(request, cookieName = 'connect.sid') {
  const value = getCookies(request)[cookieName];
  return value ? `${cookieName}=${encodeURIComponent(value)}` : '';
}

export class AuthClient {
  constructor({
    issuer = process.env.OIDC_ISSUER || defaultIssuer,
    clientId = process.env.OIDC_CLIENT_ID,
    clientSecret = process.env.OIDC_CLIENT_SECRET,
    authApiToken = process.env.AUTH_API_TOKEN,
    sessionCookieName = 'connect.sid',
  } = {}) {
    if (!clientId) {
      throw new Error('OIDC_CLIENT_ID is required');
    }
    let normalizedIssuer;
    try {
      normalizedIssuer = new URL(issuer).toString().replace(/\/$/, '');
    } catch {
      throw new Error('OIDC_ISSUER must be an absolute URL');
    }
    if (!/^https?:\/\//.test(normalizedIssuer)) {
      throw new Error('OIDC_ISSUER must use HTTP or HTTPS');
    }
    this.issuer = normalizedIssuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.authApiToken = authApiToken;
    this.sessionCookieName = sessionCookieName;
    this.removeProperty = this.deleteProperty;
    this.jwks = null;
    this.jwksExpiresAt = 0;
  }

  url(path, query) {
    const url = new URL(path, this.issuer);
    for (const [key, value] of Object.entries(query || {})) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    }
    return url;
  }

  async request(
    path,
    { method = 'GET', request, auth = 'none', body, form, headers = {}, allowEmpty = false, ...options } = {},
  ) {
    const outgoing = { ...headers };
    if (auth === 'session' || auth === 'admin') {
      const cookie = getSessionCookie(request, this.sessionCookieName);
      if (!cookie) {
        throw new Error('Authentication required: pass the incoming request');
      }
      outgoing.Cookie = cookie;
    } else if (auth === 'api') {
      if (!this.authApiToken) {
        throw new Error('An Auth API token is required');
      }
      outgoing.Authorization = `Bearer ${this.authApiToken}`;
    }
    if (form) {
      outgoing['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(form);
    }
    if (body !== undefined && !form) {
      outgoing['content-type'] = 'application/json';
      body = JSON.stringify(body);
    }
    const response = await fetch(this.url(path), { method, headers: outgoing, body, ...options });
    if (!response.ok) {
      throw new AuthApiError(method, path, response.status, await response.text());
    }
    if (allowEmpty || response.status === 204) {
      return undefined;
    }
    const text = await response.text();
    if (!text) {
      return undefined;
    }
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  getDiscovery() {
    return this.request('/.well-known/openid-configuration');
  }
  getJwks() {
    return this.request('/.well-known/jwks.json').then((keys) => {
      this.jwks = keys;
      this.jwksExpiresAt = Date.now() + 3600000;
      return keys;
    });
  }
  async verifyToken(token) {
    const { header, payload, signature, signed } = parseToken(token);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
      throw new Error('Unsupported JWT');
    }
    const keys = this.jwks && Date.now() < this.jwksExpiresAt ? this.jwks : await this.getJwks();
    const jwk = keys.keys?.find((key) => key.kid === header.kid && key.kty === 'RSA');
    if (!jwk || !verify('RSA-SHA256', signed, createPublicKey({ key: jwk, format: 'jwk' }), signature)) {
      throw new Error('Invalid JWT signature');
    }
    const now = Math.floor(Date.now() / 1000),
      audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== this.issuer || !audiences.includes(this.clientId) || typeof payload.sub !== 'string') {
      throw new Error('Invalid JWT claims');
    }
    if (typeof payload.exp !== 'number' || payload.exp <= now) {
      throw new Error('Expired JWT');
    }
    if (typeof payload.nbf === 'number' && payload.nbf > now) {
      throw new Error('JWT is not active');
    }
    return payload;
  }
  async getUserInfo(token) {
    await this.verifyToken(token);
    return this.request('/userinfo', {
      headers: { Authorization: `Bearer ${token}`, 'X-Auth-Audience': this.clientId },
    });
  }
  introspectToken(token) {
    return this.request('/oauth/introspect', {
      method: 'POST',
      form: { token, token_type_hint: 'access_token' },
      headers: {
        Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret || ''}`).toString('base64')}`,
      },
    });
  }
  revokeApiToken(token) {
    return this.request('/api/v1/revoke', {
      method: 'POST',
      form: { token, token_type_hint: 'access_token' },
      headers: {
        Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret || ''}`).toString('base64')}`,
      },
      allowEmpty: true,
    });
  }
  revokeRefreshToken(token) {
    return this.request('/revoke', {
      method: 'POST',
      form: {
        client_id: this.clientId,
        client_secret: this.clientSecret || '',
        token,
        token_type_hint: 'refresh_token',
      },
      allowEmpty: true,
    });
  }
  createAuthorizationRequest({
    redirectUri,
    scope = 'openid profile email',
    nonce = randomBytes(32).toString('base64url'),
  }) {
    if (!redirectUri) {
      throw new Error('A redirect URI is required');
    }
    const state = randomBytes(32).toString('base64url'),
      codeVerifier = randomBytes(32).toString('base64url');
    const url = this.url('/authorize', {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      state,
      scope,
      nonce,
      code_challenge: createHash('sha256').update(codeVerifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    return { url: String(url), state, codeVerifier, nonce };
  }
  authorizationUrl(options) {
    return this.createAuthorizationRequest(options).url;
  }
  exchangeCode({ code, codeVerifier, redirectUri, clientSecret = this.clientSecret }) {
    return this.request('/token', {
      method: 'POST',
      form: {
        grant_type: 'authorization_code',
        code,
        client_id: this.clientId,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        ...(clientSecret ? { client_secret: clientSecret } : {}),
      },
    });
  }
  refreshToken({ refreshToken, scope, clientSecret = this.clientSecret }) {
    if (!refreshToken) {
      throw new Error('A refresh token is required');
    }
    return this.request('/token', {
      method: 'POST',
      form: {
        grant_type: 'refresh_token',
        client_id: this.clientId,
        refresh_token: refreshToken,
        ...(scope !== undefined ? { scope } : {}),
        ...(clientSecret ? { client_secret: clientSecret } : {}),
      },
    });
  }
  getProfile(request) {
    if (!getSessionCookie(request, this.sessionCookieName)) return Promise.resolve(null);
    return this.request('/api/v1/profile', { request, auth: 'session' }).catch((error) => {
      if (error instanceof AuthApiError) return null;
      throw error;
    });
  }
  checkSession(request) {
    return this.request('/api/v1/profile', { method: 'HEAD', request, auth: 'session', allowEmpty: true });
  }
  getSessionProfile(request) {
    return this.getProfile(request);
  }
  isSessionAuthenticated(request) {
    return this.getProfile(request).then(Boolean);
  }
  async requireSession(request, response) {
    const profile = await this.getProfile(request);
    if (profile) {
      return profile;
    }
    response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Authentication required');
    return null;
  }
  signOut(request) {
    return this.request('/api/v1/profile', { method: 'DELETE', request, auth: 'session', allowEmpty: true });
  }
  setPreferredUsername(request, preferred_username) {
    return this.request('/api/v1/profile/preferred-username', {
      method: 'PUT',
      request,
      auth: 'session',
      body: { preferred_username },
    });
  }
  getProperties(request) {
    return this.request('/api/v1/properties', { request, auth: 'session' });
  }
  getProperty(request, key) {
    if (!getSessionCookie(request, this.sessionCookieName)) return Promise.resolve(null);
    return this.request(`/api/v1/properties/${encodeURIComponent(key)}`, { request, auth: 'session' }).catch(
      (error) => {
        if (error instanceof AuthApiError) return null;
        throw error;
      },
    );
  }
  setProperty(request, key, value) {
    return this.request('/api/v1/properties', { method: 'PUT', request, auth: 'session', body: { key, value } });
  }
  deleteProperty(request, key) {
    return this.request(`/api/v1/properties/${encodeURIComponent(key)}`, {
      method: 'DELETE',
      request,
      auth: 'session',
      allowEmpty: true,
    });
  }
  removeProperty(request, key) {
    return this.deleteProperty(request, key);
  }
  issueSessionToken(request, audience) {
    const origin = request?.headers?.get ? request.headers.get('origin') : request?.headers?.origin;
    if (!origin) {
      throw new Error('Origin header required to issue a session token');
    }
    return this.request('/api/v1/session/token', {
      method: 'POST',
      request,
      auth: 'session',
      headers: { Origin: origin },
      body: { audience },
    });
  }
  listUserApiTokens(request, clientId) {
    const query = clientId ? `?clientId=${encodeURIComponent(clientId)}` : '';
    return this.request(`/api/v1/api-tokens/me${query}`, { request, auth: 'session' });
  }
  listApiTokensForClient(request, clientId) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`, { request, auth: 'admin' });
  }
  createApiToken(request, clientId, data) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`, {
      method: 'POST',
      request,
      auth: 'admin',
      body: data,
    });
  }
  deleteApiToken(request, clientId, tokenId) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
      allowEmpty: true,
    });
  }
  listUserApiTokensForClient(request, clientId) {
    return this.listApiTokensForClient(request, clientId);
  }
  createUserApiToken(request, clientId, data) {
    return this.createApiToken(request, clientId, data);
  }
  deleteUserApiToken(request, clientId, tokenId) {
    return this.deleteApiToken(request, clientId, tokenId);
  }
  mintApiToken({ label, scopes }) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(this.clientId)}/issue`, {
      method: 'POST',
      auth: 'api',
      body: { label, scopes },
    });
  }
  listOidcClients(request) {
    return this.request('/api/v1/oidc/clients', { request, auth: 'admin' });
  }
  createOidcClient(request, data) {
    return this.request('/api/v1/oidc/clients', { method: 'POST', request, auth: 'admin', body: data });
  }
  deleteOidcClient(request, id) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
      allowEmpty: true,
    });
  }
  setClientLogoutRedirects(request, id, postLogoutRedirectUris) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/logout-redirects`, {
      method: 'PUT',
      request,
      auth: 'admin',
      body: { postLogoutRedirectUris },
    });
  }
  regenerateOidcClientSecret(request, id) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/secret`, {
      method: 'PUT',
      request,
      auth: 'admin',
    });
  }
  setOidcClientScopes(request, id, scopes) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/scopes`, {
      method: 'PUT',
      request,
      auth: 'admin',
      body: { scopes },
    });
  }
  listAuthApiTokens(request, clientId) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}`, { request, auth: 'admin' });
  }
  createAuthApiToken(request, clientId, label) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}`, {
      method: 'POST',
      request,
      auth: 'admin',
      body: { label },
    });
  }
  deleteAuthApiToken(request, clientId, tokenId) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
      allowEmpty: true,
    });
  }
  getKeys(request) {
    return this.request('/api/v1/keys', { request, auth: 'admin' });
  }
  rotateKeys(request) {
    return this.request('/api/v1/keys/rotate', { method: 'POST', request, auth: 'admin' });
  }
  getAudit(request, query = {}) {
    const url = this.url('/api/v1/audit', query);
    return this.request(url.pathname + url.search, { request, auth: 'session' });
  }
  getAuditOptions(request) {
    return this.request('/api/v1/audit/options', { request, auth: 'session' });
  }
  listAdminUsers(request) {
    return this.request('/api/v1/admin/users', { request, auth: 'admin' });
  }
  updateAdminUser(request, id, data) {
    return this.request(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      request,
      auth: 'admin',
      body: data,
    });
  }
  deleteAdminUser(request, id) {
    return this.request(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
    });
  }
  getLogoutUrl({ idTokenHint, postLogoutRedirectUri, state } = {}) {
    return String(
      this.url('/logout', {
        client_id: this.clientId,
        id_token_hint: idTokenHint,
        post_logout_redirect_uri: postLogoutRedirectUri,
        state,
      }),
    );
  }
  getCookies(request) {
    return getCookies(request);
  }
}

export function createAuthClient(options = {}) {
  return new AuthClient(options);
}

const authClient = new AuthClient();
export default authClient;
