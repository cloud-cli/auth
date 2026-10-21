const authDomain = '__API_URL__';
let profileRequest;

function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decode(value) {
  return Uint8Array.from(
    atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4)),
    (character) => character.charCodeAt(0),
  );
}

function credentialJSON(credential) {
  const response = credential.response;
  const isRegistration = 'attestationObject' in response;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    transports: response.getTransports?.() || [],
    response: isRegistration
      ? { clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(response.attestationObject) }
      : {
          clientDataJSON: encode(response.clientDataJSON),
          authenticatorData: encode(response.authenticatorData),
          signature: encode(response.signature),
          userHandle: response.userHandle ? encode(response.userHandle) : null,
        },
  };
}

export async function registerPasskey(label = 'Passkey') {
  const optionsResponse = await fetch(new URL('/api/v1/webauthn/register/options', authDomain), {
    credentials: 'include',
  });
  if (!optionsResponse.ok) throw new Error('Could not create passkey registration options');
  const options = await optionsResponse.json();
  options.challenge = decode(options.challenge);
  options.user.id = decode(options.user.id);
  options.excludeCredentials = (options.excludeCredentials || []).map((item) => ({ ...item, id: decode(item.id) }));
  const credential = await navigator.credentials.create({ publicKey: options });
  const response = await fetch(new URL('/api/v1/webauthn/register/verify', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...credentialJSON(credential), label }),
  });
  if (!response.ok) throw new Error('Could not register passkey');
  return response.json();
}

export async function signInWithPasskey(loginHint = '') {
  const endpoint = new URL('/api/v1/webauthn/authentication/options', authDomain);
  if (loginHint) endpoint.searchParams.set('login_hint', loginHint);
  const optionsResponse = await fetch(endpoint, { credentials: 'include' });
  if (!optionsResponse.ok) throw new Error('Could not create passkey authentication options');
  const options = await optionsResponse.json();
  options.challenge = decode(options.challenge);
  options.allowCredentials = (options.allowCredentials || []).map((item) => ({ ...item, id: decode(item.id) }));
  const credential = await navigator.credentials.get({ publicKey: options });
  const response = await fetch(new URL('/api/v1/webauthn/authentication/verify', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(credentialJSON(credential)),
  });
  if (!response.ok) throw new Error('Could not authenticate with passkey');
}

export async function getPasskeys() {
  const response = await fetch(new URL('/api/v1/webauthn/credentials', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load passkeys');
  return response.json();
}

export async function getProfile() {
  if (!profileRequest) {
    profileRequest = fetch(new URL('/api/v1/profile', authDomain), { credentials: 'include' }).then(
      async (response) => {
        if (!response.ok) throw new Error('Could not load profile');
        return response.json();
      },
    );
    profileRequest.catch(() => (profileRequest = undefined));
  }
  return profileRequest;
}

export async function setPreferredUsername(preferredUsername) {
  const response = await fetch(new URL('/api/v1/profile/preferred-username', authDomain), {
    credentials: 'include',
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ preferred_username: preferredUsername }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not set preferred username.');
  return result;
}

export async function revokePasskey(credentialId) {
  const response = await fetch(
    new URL('/api/v1/webauthn/credentials/' + encodeURIComponent(credentialId), authDomain),
    {
      credentials: 'include',
      method: 'DELETE',
    },
  );
  if (!response.ok) throw new Error('Could not revoke passkey');
}

export async function generateRecoveryCodes() {
  const response = await fetch(new URL('/api/v1/recovery-codes', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  if (!response.ok) throw new Error('Could not generate recovery codes');
  return (await response.json()).codes;
}

export async function getProperties() {
  const response = await fetch(new URL('/api/v1/properties', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load properties');
  return response.json();
}

export async function setProperty(key, value) {
  const response = await fetch(new URL('/api/v1/properties', authDomain), {
    credentials: 'include',
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ key, value }),
  });
  if (!response.ok) throw new Error('Could not save property');
}

export async function deleteProperty(key) {
  const response = await fetch(new URL('/api/v1/properties/' + encodeURIComponent(key), authDomain), {
    credentials: 'include',
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Could not remove property');
}

export async function getOidcClients() {
  const response = await fetch(new URL('/api/v1/oidc/apps', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load OIDC clients');
  return response.json();
}

export async function createOidcClient(name, redirectUris, scopes, isPublic = false, postLogoutRedirectUris = []) {
  const response = await fetch(new URL('/api/v1/oidc/clients', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, redirectUris, scopes, isPublic, postLogoutRedirectUris }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not create OIDC client');
  return result;
}

export async function updateOidcClientName(id, name) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/name', authDomain), {
    credentials: 'include',
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not update application name');
  return result;
}

export async function setOidcClientAvailability(id, availableToUsers) {
  const response = await fetch(
    new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/availability', authDomain),
    {
      credentials: 'include',
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ availableToUsers }),
    },
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not update application availability');
  return result;
}

export async function getAgents() {
  const response = await fetch(new URL('/api/v1/agents', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load Agents');
  return response.json();
}

export async function createAgent(name) {
  const response = await fetch(new URL('/api/v1/agents', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not create Agent');
  return result;
}

export async function disableAgent(agentId) {
  const response = await fetch(new URL('/api/v1/agents/' + encodeURIComponent(agentId), authDomain), {
    credentials: 'include',
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Could not disable Agent');
}

export async function getAgentTokens(agentId) {
  const response = await fetch(new URL('/api/v1/agents/' + encodeURIComponent(agentId) + '/tokens', authDomain), {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Could not load Agent sign-in tokens');
  return response.json();
}

export async function createAgentToken(agentId, label) {
  const response = await fetch(new URL('/api/v1/agents/' + encodeURIComponent(agentId) + '/tokens', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ label }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not create Agent sign-in token');
  return result;
}

export async function revokeAgentToken(agentId, tokenId) {
  const response = await fetch(
    new URL('/api/v1/agents/' + encodeURIComponent(agentId) + '/tokens/' + encodeURIComponent(tokenId), authDomain),
    { credentials: 'include', method: 'DELETE' },
  );
  if (!response.ok) throw new Error('Could not revoke Agent sign-in token');
}

export async function rotateAgentToken(agentId, tokenId) {
  const response = await fetch(
    new URL(
      '/api/v1/agents/' + encodeURIComponent(agentId) + '/tokens/' + encodeURIComponent(tokenId) + '/rotate',
      authDomain,
    ),
    { credentials: 'include', method: 'POST' },
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not rotate Agent sign-in token');
  return result;
}

export async function removeOidcClient(id) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id), authDomain), {
    credentials: 'include',
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Could not remove OIDC client');
}

export async function regenerateOidcClientSecret(id) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/secret', authDomain), {
    credentials: 'include',
    method: 'PUT',
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not regenerate OIDC client secret');
  return result;
}

export async function addOidcScopes(id, scopes) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/scopes', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scopes }),
  });
  if (!response.ok) throw new Error('Could not add OIDC scopes');
  return response.json();
}

export async function updateOidcScopes(id, scopes) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/scopes', authDomain), {
    credentials: 'include',
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scopes }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not update OIDC scopes');
  return result;
}

export async function updateOidcCallbacks(id, redirectUris) {
  const response = await fetch(new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/callbacks', authDomain), {
    credentials: 'include',
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirectUris }),
  });
  if (!response.ok) throw new Error('Could not update callback URLs');
  return response.json();
}

export async function updateOidcLogoutRedirects(id, postLogoutRedirectUris) {
  const response = await fetch(
    new URL('/api/v1/oidc/clients/' + encodeURIComponent(id) + '/logout-redirects', authDomain),
    {
      credentials: 'include',
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ postLogoutRedirectUris }),
    },
  );
  if (!response.ok) throw new Error('Could not update post-logout redirect URLs');
  return response.json();
}

export async function getAuditEvents({ app = '', event = '', offset = 0 } = {}) {
  const url = new URL('/api/v1/audit', authDomain);
  url.searchParams.set('limit', '20');
  url.searchParams.set('offset', String(offset));
  if (app) url.searchParams.set('app', app);
  if (event) url.searchParams.set('event', event);
  const response = await fetch(url, { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load authentication history');
  return response.json();
}

export async function getAuditOptions() {
  const response = await fetch(new URL('/api/v1/audit/options', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load audit filters');
  return response.json();
}

export async function getSigningKeys() {
  const response = await fetch(new URL('/api/v1/keys', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load signing keys');
  return response.json();
}

export async function getApiTokens(clientId) {
  const response = await fetch(new URL('/api/v1/api-tokens/' + encodeURIComponent(clientId), authDomain), {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Could not load API tokens');
  return response.json();
}

export async function getAllApiTokens() {
  const response = await fetch(new URL('/api/v1/api-tokens/me', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load API tokens');
  return response.json();
}

export async function createApiToken(clientId, label, scopes) {
  const response = await fetch(new URL('/api/v1/api-tokens/' + encodeURIComponent(clientId), authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ label, scopes }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not create API token');
  return result;
}

export async function revokeApiToken(clientId, tokenId) {
  const response = await fetch(
    new URL('/api/v1/api-tokens/' + encodeURIComponent(clientId) + '/' + encodeURIComponent(tokenId), authDomain),
    { credentials: 'include', method: 'DELETE' },
  );
  if (!response.ok) throw new Error('Could not revoke API token');
}

export async function updateApiTokenScopes(clientId, tokenId, scopes) {
  const response = await fetch(
    new URL(
      '/api/v1/api-tokens/' + encodeURIComponent(clientId) + '/' + encodeURIComponent(tokenId) + '/scopes',
      authDomain,
    ),
    {
      credentials: 'include',
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scopes }),
    },
  );
  if (!response.ok) {
    const result = await response.json();
    throw new Error(result.error || 'Could not update API token scopes');
  }
}

export async function getAuthApiTokens(clientId) {
  const response = await fetch(new URL('/api/v1/auth-api-tokens/' + encodeURIComponent(clientId), authDomain), {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Could not load Admin keys');
  return response.json();
}

export async function createAuthApiToken(clientId, label) {
  const response = await fetch(new URL('/api/v1/auth-api-tokens/' + encodeURIComponent(clientId), authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ label }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Could not create Admin key');
  return result;
}

export async function revokeAuthApiToken(clientId, tokenId) {
  const response = await fetch(
    new URL('/api/v1/auth-api-tokens/' + encodeURIComponent(clientId) + '/' + encodeURIComponent(tokenId), authDomain),
    { credentials: 'include', method: 'DELETE' },
  );
  if (!response.ok) throw new Error('Could not revoke Admin key');
}

export async function rotateSigningKey() {
  const response = await fetch(new URL('/api/v1/keys/rotate', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  if (!response.ok) throw new Error('Could not rotate signing key');
  return response.json();
}
