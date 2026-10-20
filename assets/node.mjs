/**
 * Node.js client for Auth-specific APIs. OIDC protocol flows are provided by
 * `openid-client`. `OIDC_ISSUER` defaults to this service's issuer;
 * `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `AUTH_API_TOKEN` are optional for applicable Auth API operations. Named utilities and session helpers can
 * be imported without configuring a client ID.
 *
 * @example
 * import client from './node.mjs';
 * const profile = await client.getProfile(request);
 */
const defaultIssuer = '__API_URL__';
class AuthApiError extends Error {
  /**
   * Create an error for a non-successful Auth API response.
   * @param {string} method
   * @param {string} path
   * @param {number} status
   * @param {string} detail
   * @returns {void}
   */
  constructor(method, path, status, detail) {
    super(`Auth request ${method} ${path} failed: ${status} ${detail}`);
    this.name = 'AuthApiError';
    this.status = status;
  }
}

/**
 * Read and decode cookies from a Fetch or Node-style request.
 * @param {Request|object} request
 * @returns {Record<string, string>}
 */
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

/**
 * Format one incoming session cookie for an outbound Cookie header; authorization and admin roles are still enforced by Auth.
 * @param {Request|object} request
 * @param {string} [cookieName='connect.sid']
 * @returns {string}
 */
export function getSessionCookie(request, cookieName = 'connect.sid') {
  const value = getCookies(request)[cookieName];
  return value ? `${cookieName}=${encodeURIComponent(value)}` : '';
}

/**
 * Client for Auth-specific user-session, API-token, and administrator endpoints. The default export is an environment-configured instance.
 */
export class AuthClient {
  /**
   * Configure the Auth issuer and API credentials; OIDC protocol operations are handled by `openid-client`.
   * @param {{issuer?: string, clientId?: string, clientSecret?: string, authApiToken?: string, sessionCookieName?: string}} [options]
   * @returns {void}
   */
  constructor({
    issuer = process.env.OIDC_ISSUER || defaultIssuer,
    clientId = process.env.OIDC_CLIENT_ID,
    clientSecret = process.env.OIDC_CLIENT_SECRET,
    authApiToken = process.env.AUTH_API_TOKEN,
    sessionCookieName = 'connect.sid',
  } = {}) {
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
    this.issuerOrigin = new URL(normalizedIssuer).origin;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.authApiToken = authApiToken;
    this.sessionCookieName = sessionCookieName;
    this.removeProperty = this.deleteProperty;
  }

  /**
   * Require a configured client ID for client-bound Auth API operations.
   * @returns {string}
   */
  requireClientId() {
    if (!this.clientId) {
      throw new Error('OIDC_CLIENT_ID is required for this operation');
    }
    return this.clientId;
  }

  /**
   * Build an Auth issuer URL with optional query parameters.
   * @param {string} path
   * @param {Record<string, string>} [query]
   * @returns {URL}
   */
  url(path, query) {
    const url = new URL(path, this.issuer);
    for (const [key, value] of Object.entries(query || {})) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    }
    return url;
  }

  /**
   * Send a request to the issuer; `session` forwards the user's session cookie, `admin` forwards an admin session cookie, and `api` uses the configured Auth API bearer token. `form` is URL-encoded, `body` is JSON, and extra options are passed to fetch.
   * @param {string} path
   * @param {{method?: string, request?: Request|object, auth?: 'none'|'session'|'admin'|'api', body?: unknown, form?: Record<string, string>, headers?: Record<string, string>, allowEmpty?: boolean, [fetchOption: string]: unknown}} [options]
   * @returns {Promise<unknown>}
   */
  async request(
    path,
    { method = 'GET', request, auth = 'none', body, form, headers = {}, allowEmpty = false, ...options } = {},
  ) {
    const url = this.url(path);
    if (url.origin !== this.issuerOrigin) {
      throw new Error('Auth request URL must use the configured issuer origin');
    }
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
    const response = await fetch(url, { method, headers: outgoing, body, ...options, redirect: 'manual' });
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

  /**
   * Revoke a token at `/api/v1/revoke` using client Basic authentication (OIDC client secret).
   * @param {string} token
   * @returns {Promise<void>}
   */
  revokeApiToken(token) {
    this.requireClientId();
    return this.request('/api/v1/revoke', {
      method: 'POST',
      form: { token, token_type_hint: 'access_token' },
      headers: {
        Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret || ''}`).toString('base64')}`,
      },
      allowEmpty: true,
    });
  }
  /**
   * Get the profile via `/api/v1/profile` using the user's session cookie; returns null when unauthenticated or denied.
   * @param {Request|object} request
   * @returns {Promise<unknown|null>}
   */
  getProfile(request) {
    if (!getSessionCookie(request, this.sessionCookieName)) return Promise.resolve(null);
    return this.request('/api/v1/profile', { request, auth: 'session' }).catch((error) => {
      if (error instanceof AuthApiError && [401, 403, 404].includes(error.status)) return null;
      throw error;
    });
  }
  /**
   * Check the user's session with `HEAD /api/v1/profile`.
   * @param {Request|object} request
   * @returns {Promise<void>}
   */
  checkSession(request) {
    return this.request('/api/v1/profile', { method: 'HEAD', request, auth: 'session', allowEmpty: true });
  }
  /**
   * Alias for getProfile; uses the user's session cookie.
   * @param {Request|object} request
   * @returns {Promise<unknown|null>}
   */
  getSessionProfile(request) {
    return this.getProfile(request);
  }
  /**
   * Resolve whether the user's session is authenticated.
   * @param {Request|object} request
   * @returns {Promise<boolean>}
   */
  isSessionAuthenticated(request) {
    return this.getProfile(request).then(Boolean);
  }
  /**
   * Return the profile or write an HTTP 401 response when the session is absent/invalid.
   * @param {Request|object} request
   * @param {object} response
   * @returns {Promise<unknown|null>}
   */
  async requireSession(request, response) {
    const profile = await this.getProfile(request);
    if (profile) {
      return profile;
    }
    response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Authentication required');
    return null;
  }
  /**
   * Sign out the current user via `DELETE /api/v1/profile` using their session cookie.
   * @param {Request|object} request
   * @returns {Promise<void>}
   */
  signOut(request) {
    return this.request('/api/v1/profile', { method: 'DELETE', request, auth: 'session', allowEmpty: true });
  }
  /**
   * Update the current user's preferred username via the session-authenticated profile endpoint.
   * @param {Request|object} request
   * @param {string} preferred_username
   * @returns {Promise<unknown>}
   */
  setPreferredUsername(request, preferred_username) {
    return this.request('/api/v1/profile/preferred-username', {
      method: 'PUT',
      request,
      auth: 'session',
      body: { preferred_username },
    });
  }
  /**
   * List the current user's properties using their session cookie.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  getProperties(request) {
    return this.request('/api/v1/properties', { request, auth: 'session' });
  }
  /**
   * Get one session-authenticated property; returns null when absent or denied.
   * @param {Request|object} request
   * @param {string} key
   * @returns {Promise<unknown|null>}
   */
  getProperty(request, key) {
    if (!getSessionCookie(request, this.sessionCookieName)) return Promise.resolve(null);
    return this.request(`/api/v1/properties/${encodeURIComponent(key)}`, { request, auth: 'session' }).catch(
      (error) => {
        if (error instanceof AuthApiError && [401, 403, 404].includes(error.status)) return null;
        throw error;
      },
    );
  }
  /**
   * Set a property for the current user via `PUT /api/v1/properties`.
   * @param {Request|object} request
   * @param {string} key
   * @param {unknown} value
   * @returns {Promise<unknown>}
   */
  setProperty(request, key, value) {
    return this.request('/api/v1/properties', { method: 'PUT', request, auth: 'session', body: { key, value } });
  }
  /**
   * Delete a current-user property via `DELETE /api/v1/properties/{key}`.
   * @param {Request|object} request
   * @param {string} key
   * @returns {Promise<void>}
   */
  deleteProperty(request, key) {
    return this.request(`/api/v1/properties/${encodeURIComponent(key)}`, {
      method: 'DELETE',
      request,
      auth: 'session',
      allowEmpty: true,
    });
  }
  /**
   * Alias for deleteProperty.
   * @param {Request|object} request
   * @param {string} key
   * @returns {Promise<void>}
   */
  removeProperty(request, key) {
    return this.deleteProperty(request, key);
  }
  /**
   * Issue a session-bound token for an audience using the user's session and request Origin.
   * @param {Request|object} request
   * @param {string} audience
   * @returns {Promise<unknown>}
   */
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
  /**
   * List the current user's API tokens, optionally filtered by client ID; uses their session cookie.
   * @param {Request|object} request
   * @param {string} [clientId]
   * @returns {Promise<unknown>}
   */
  listUserApiTokens(request, clientId) {
    const query = clientId ? `?clientId=${encodeURIComponent(clientId)}` : '';
    return this.request(`/api/v1/api-tokens/me${query}`, { request, auth: 'session' });
  }
  /**
   * List the current user's API tokens for an available client.
   * @param {Request|object} request
   * @param {string} clientId
   * @returns {Promise<unknown>}
   */
  listApiTokensForClient(request, clientId) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`, { request, auth: 'session' });
  }
  /**
   * Create a client API token using the current user's session.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {object} data
   * @returns {Promise<unknown>}
   */
  createApiToken(request, clientId, data) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}`, {
      method: 'POST',
      request,
      auth: 'session',
      body: data,
    });
  }
  /**
   * Delete one of the current user's API tokens.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {string} tokenId
   * @returns {Promise<void>}
   */
  deleteApiToken(request, clientId, tokenId) {
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(clientId)}/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
      request,
      auth: 'session',
      allowEmpty: true,
    });
  }
  /**
   * Alias for listApiTokensForClient.
   * @param {Request|object} request
   * @param {string} clientId
   * @returns {Promise<unknown>}
   */
  listUserApiTokensForClient(request, clientId) {
    return this.listApiTokensForClient(request, clientId);
  }
  /**
   * Alias for createApiToken.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {object} data
   * @returns {Promise<unknown>}
   */
  createUserApiToken(request, clientId, data) {
    return this.createApiToken(request, clientId, data);
  }
  /**
   * Alias for deleteApiToken.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {string} tokenId
   * @returns {Promise<void>}
   */
  deleteUserApiToken(request, clientId, tokenId) {
    return this.deleteApiToken(request, clientId, tokenId);
  }
  /**
   * Mint a downstream API token via `/api/v1/api-tokens/{clientId}/issue` using the configured Auth API bearer token, not OIDC client credentials.
   * @param {{label: string, scopes: string[]}} options
   * @returns {Promise<unknown>}
   */
  mintApiToken({ label, scopes }) {
    this.requireClientId();
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(this.clientId)}/issue`, {
      method: 'POST',
      auth: 'api',
      body: { label, scopes },
    });
  }
  /**
   * Append downstream scopes to this client's scope list with the configured Auth API bearer token. Existing scopes cannot be removed through this operation.
   * @param {string[]} scopes
   * @returns {Promise<{scopes: string[]}>}
   */
  addApiTokenScopes(scopes) {
    this.requireClientId();
    return this.request(`/api/v1/api-tokens/${encodeURIComponent(this.clientId)}/scopes`, {
      method: 'POST',
      auth: 'api',
      body: { scopes },
    });
  }
  /**
   * List OIDC clients visible to the current account.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  listOidcClients(request) {
    return this.request('/api/v1/oidc/apps', { request, auth: 'session' });
  }
  /**
   * Create an OIDC client; the server generates an immutable client ID and may return its one-time secret.
   * @param {Request|object} request
   * @param {{name: string, redirectUris: string[], postLogoutRedirectUris?: string[], scopes?: string[], isPublic?: boolean}} data
   * @returns {Promise<unknown>}
   */
  createOidcClient(request, data) {
    return this.request('/api/v1/oidc/clients', { method: 'POST', request, auth: 'session', body: data });
  }
  /**
   * Delete an OIDC client owned by the current account, or any client when an administrator.
   * @param {Request|object} request
   * @param {string} id
   * @returns {Promise<void>}
   */
  deleteOidcClient(request, id) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      request,
      auth: 'session',
      allowEmpty: true,
    });
  }
  /**
   * Replace a client's registered post-logout redirect URLs.
   * @param {Request|object} request
   * @param {string} id
   * @param {string[]} postLogoutRedirectUris
   * @returns {Promise<unknown>}
   */
  setClientLogoutRedirects(request, id, postLogoutRedirectUris) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/logout-redirects`, {
      method: 'PUT',
      request,
      auth: 'session',
      body: { postLogoutRedirectUris },
    });
  }
  /**
   * Regenerate an OIDC client's secret; the new secret may be returned once.
   * @param {Request|object} request
   * @param {string} id
   * @returns {Promise<unknown>}
   */
  regenerateOidcClientSecret(request, id) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/secret`, {
      method: 'PUT',
      request,
      auth: 'session',
    });
  }
  /**
   * Replace an OIDC client's scopes.
   * @param {Request|object} request
   * @param {string} id
   * @param {string[]} scopes
   * @returns {Promise<unknown>}
   */
  setOidcClientScopes(request, id, scopes) {
    return this.request(`/api/v1/oidc/clients/${encodeURIComponent(id)}/scopes`, {
      method: 'PUT',
      request,
      auth: 'session',
      body: { scopes },
    });
  }
  /**
   * List a client's Auth API tokens using the admin session.
   * @param {Request|object} request
   * @param {string} clientId
   * @returns {Promise<unknown>}
   */
  listAuthApiTokens(request, clientId) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}`, { request, auth: 'admin' });
  }
  /**
   * Create a client's fixed-purpose Auth API token using the admin session; its bearer value is returned only once.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {string} label
   * @returns {Promise<unknown>}
   */
  createAuthApiToken(request, clientId, label) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}`, {
      method: 'POST',
      request,
      auth: 'admin',
      body: { label },
    });
  }
  /**
   * Delete a client's Auth API token using the admin session.
   * @param {Request|object} request
   * @param {string} clientId
   * @param {string} tokenId
   * @returns {Promise<void>}
   */
  deleteAuthApiToken(request, clientId, tokenId) {
    return this.request(`/api/v1/auth-api-tokens/${encodeURIComponent(clientId)}/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
      allowEmpty: true,
    });
  }
  /**
   * Retrieve signing keys using the admin session.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  getKeys(request) {
    return this.request('/api/v1/keys', { request, auth: 'admin' });
  }
  /**
   * Rotate signing keys using the admin session; affects issued-token signing keys.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  rotateKeys(request) {
    return this.request('/api/v1/keys/rotate', { method: 'POST', request, auth: 'admin' });
  }
  /**
   * Query audit records using the user's session cookie.
   * @param {Request|object} request
   * @param {Record<string, string>} [query]
   * @returns {Promise<unknown>}
   */
  getAudit(request, query = {}) {
    const url = this.url('/api/v1/audit', query);
    return this.request(url.pathname + url.search, { request, auth: 'session' });
  }
  /**
   * Fetch audit filter options using the user's session cookie.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  getAuditOptions(request) {
    return this.request('/api/v1/audit/options', { request, auth: 'session' });
  }
  /**
   * List administrator accounts using the admin session cookie.
   * @param {Request|object} request
   * @returns {Promise<unknown>}
   */
  listAdminUsers(request) {
    return this.request('/api/v1/admin/users', { request, auth: 'admin' });
  }
  /**
   * Update a user account using the admin session.
   * @param {Request|object} request
   * @param {string} id
   * @param {object} data
   * @returns {Promise<unknown>}
   */
  updateAdminUser(request, id, data) {
    return this.request(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      request,
      auth: 'admin',
      body: data,
    });
  }
  /**
   * Delete a user account using the admin session.
   * @param {Request|object} request
   * @param {string} id
   * @returns {Promise<unknown>}
   */
  deleteAdminUser(request, id) {
    return this.request(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      request,
      auth: 'admin',
    });
  }
  /**
   * Read cookies from an incoming request.
   * @param {Request|object} request
   * @returns {Record<string, string>}
   */
  getCookies(request) {
    return getCookies(request);
  }
}

/**
 * Create another AuthClient from explicit options or environment defaults.
 * @param {object} [options]
 * @returns {AuthClient}
 */
export function createAuthClient(options = {}) {
  return new AuthClient(options);
}

const authClient = new AuthClient();
export default authClient;
