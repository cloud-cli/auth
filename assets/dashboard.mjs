const authDomain = "__API_URL__";

function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), (character) => character.charCodeAt(0));
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
      : { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null },
  };
}

export async function registerPasskey(label = 'Passkey') {
  const optionsResponse = await fetch(new URL('/webauthn/register/options', authDomain), { credentials: 'include' });
  if (!optionsResponse.ok) throw new Error('Could not create passkey registration options');
  const options = await optionsResponse.json();
  options.challenge = decode(options.challenge);
  options.user.id = decode(options.user.id);
  options.excludeCredentials = (options.excludeCredentials || []).map((item) => ({ ...item, id: decode(item.id) }));
  const credential = await navigator.credentials.create({ publicKey: options });
  const response = await fetch(new URL('/webauthn/register/verify', authDomain), { credentials: 'include', method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...credentialJSON(credential), label }) });
  if (!response.ok) throw new Error('Could not register passkey');
  return response.json();
}

export async function signInWithPasskey(loginHint = '') {
  const endpoint = new URL('/webauthn/authentication/options', authDomain);
  if (loginHint) endpoint.searchParams.set('login_hint', loginHint);
  const optionsResponse = await fetch(endpoint, { credentials: 'include' });
  if (!optionsResponse.ok) throw new Error('Could not create passkey authentication options');
  const options = await optionsResponse.json();
  options.challenge = decode(options.challenge);
  options.allowCredentials = (options.allowCredentials || []).map((item) => ({ ...item, id: decode(item.id) }));
  const credential = await navigator.credentials.get({ publicKey: options });
  const response = await fetch(new URL('/webauthn/authentication/verify', authDomain), { credentials: 'include', method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(credentialJSON(credential)) });
  if (!response.ok) throw new Error('Could not authenticate with passkey');
}

export async function getPasskeys() {
  const response = await fetch(new URL('/webauthn/credentials', authDomain), { credentials: 'include' });
  if (!response.ok) throw new Error('Could not load passkeys');
  return response.json();
}

export async function revokePasskey(credentialId) {
  const response = await fetch(new URL('/webauthn/credentials/' + encodeURIComponent(credentialId), authDomain), { credentials: 'include', method: 'DELETE' });
  if (!response.ok) throw new Error('Could not revoke passkey');
}

export async function generateRecoveryCodes() {
  const response = await fetch(new URL('/recovery-codes', authDomain), { credentials: 'include', method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  if (!response.ok) throw new Error('Could not generate recovery codes');
  return (await response.json()).codes;
}
