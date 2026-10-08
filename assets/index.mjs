const authDomain = '__API_URL__';
const commandQueue = {};
let popup = null;
let signInPending = false;
let pollTimer = null;
let closeTimer = null;
let signInNonce = null;
let profilePollInFlight = false;

if (!authDomain) {
  throw new Error('Failed to load authentication endpoint!');
}

const embedded = new Promise((resolve, reject) => {
  const frame = document.createElement('iframe');
  frame.src = String(new URL('/ui/embed.html', authDomain));

  Object.assign(frame.style, {
    width: '0px',
    height: '0px',
    display: 'none',
    zIndex: '-1',
    position: 'absolute',
    left: '-10px',
    top: '-10px',
  });

  frame.onload = () => resolve(frame.contentWindow);
  frame.onerror = (e) => reject(e);

  const init = () => {
    document.body.append(frame);
    setInterval(() => !popup && frame.contentWindow.postMessage({ command: 'ping' }, authDomain), 1000 * 30);
  };

  if (['complete', 'interactive'].includes(document.readyState)) {
    init();
  } else {
    window.addEventListener('DOMContentLoaded', init);
  }
});

window.addEventListener('message', (e) => {
  if (e.origin !== authDomain) {
    console.log('Unsafe event', e);
    return;
  }

  const { event, detail } = e.data || {};

  if (!event) {
    return;
  }

  switch (event) {
    case 'error':
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].reject(detail.error);
        delete commandQueue[detail.id];
      }
      break;
    case 'success':
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].resolve(detail.result);
        delete commandQueue[detail.id];
      }
      break;
    case 'signin':
      if (signInPending && e.source === popup && detail?.nonce === signInNonce) {
        if (detail.profile) finishSignIn(detail.profile);
        else
          getProfile()
            .then(finishSignIn)
            .catch(() => {});
      }
      break;

    default:
      events.dispatchEvent(new CustomEvent(event, { detail }));
  }
});

export const events = new EventTarget();
function finishSignIn(profile) {
  if (!signInPending || !profile) return;
  clearInterval(pollTimer);
  clearTimeout(closeTimer);
  pollTimer = null;
  closeTimer = null;
  signInPending = false;
  if (popup && !popup.closed) popup.close();
  popup = null;
  signInNonce = null;
  profilePollInFlight = false;
  events.dispatchEvent(new CustomEvent('signin', { detail: profile }));
  events.dispatchEvent(new CustomEvent('state', { detail: profile }));
}
function startProfilePoll() {
  const poll = async () => {
    if (!signInPending) return;
    if (popup && !popup.closed) {
      popup.postMessage({ event: 'auth-popup-ping', detail: { nonce: signInNonce } }, authDomain);
      clearTimeout(closeTimer);
      closeTimer = null;
    } else if (popup?.closed && !closeTimer) {
      closeTimer = setTimeout(() => {
        if (signInPending && popup?.closed) {
          clearInterval(pollTimer);
          pollTimer = null;
          closeTimer = null;
          signInPending = false;
          popup = null;
          signInNonce = null;
        }
      }, 10_000);
    }

    if (!profilePollInFlight) {
      profilePollInFlight = true;
      getProfile()
        .then((profile) => finishSignIn(profile))
        .catch(() => {})
        .finally(() => {
          profilePollInFlight = false;
        });
    }
  };
  poll();
  pollTimer = setInterval(poll, 700);
}
export function postMessage(message) {
  embedded.then((window) => window.postMessage(message));
}

function createSignInNonce() {
  if (window.crypto?.getRandomValues) {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

export function signIn(usePopUp) {
  if (usePopUp) {
    if (signInPending && popup && !popup.closed) return;
    clearInterval(pollTimer);
    clearTimeout(closeTimer);
    signInPending = true;
    signInNonce = createSignInNonce();
    const { innerWidth, innerHeight } = window;
    const left = Math.round((innerWidth - 640) / 2);
    const top = Math.round((innerHeight - 480) / 2);

    const loginUrl = new URL('/login', authDomain);
    loginUrl.searchParams.set('signinNonce', signInNonce);
    popup = window.open(String(loginUrl), 'signin', `popup,width=640,height=630,left=${left},top=${top}`);
    if (!popup) {
      signInPending = false;
      signInNonce = null;
      location.href = String(new URL('/login?url=' + encodeURIComponent(location.href), authDomain));
      return;
    }
    startProfilePoll();
    return;
  }

  const url = new URL('/login?url=' + encodeURIComponent(location.href), authDomain);

  location.href = String(url);
}

function fetchCommand(command, runAfter) {
  return async (...args) =>
    new Promise((resolve, reject) => {
      const id = Math.random();
      commandQueue[id] = {
        resolve: (x) => {
          runAfter && runAfter(x);
          resolve(x);
        },
        reject,
      };
      embedded.then((w) => w.postMessage({ id, command, args }, authDomain));
    });
}

let ns = location.host;
const tokens = new Map();
const getNS = (p) => ns + ':' + p;

export function setNS(newNS) {
  ns = newNS;
}

export function getPropertyNS(property) {
  return getProperty(getNS(property));
}

export function setPropertyNS(property, value) {
  return setProperty(getNS(property), value);
}

export function deletePropertyNS(property) {
  return deleteProperty(getNS(property));
}

export const getProperty = fetchCommand('getProperty');
export const setProperty = fetchCommand('setProperty');
export const deleteProperty = fetchCommand('deleteProperty');
export const getProperties = fetchCommand('getProperties');
export async function getProfile() {
  try {
    const response = await fetch(new URL('/api/v1/profile', authDomain), { credentials: 'include', mode: 'cors' });
    if (!response.ok) throw new Error(response.status + ': ' + response.statusText);
    return response.json();
  } catch {
    return fetchCommand('getProfile')();
  }
}
export async function isAuthenticated() {
  try {
    const response = await fetch(new URL('/api/v1/profile', authDomain), {
      credentials: 'include',
      mode: 'cors',
      method: 'HEAD',
    });
    return response.ok && response.status < 300;
  } catch {
    return fetchCommand('isAuthenticated')();
  }
}
export const signOut = fetchCommand('signOut', () => {
  events.dispatchEvent(new CustomEvent('signout'));
  events.dispatchEvent(new CustomEvent('state', { detail: null }));
});

export async function getAccessToken(audience) {
  const cached = tokens.get(audience);
  if (cached && cached.expiresAt > Date.now() + 30_000) return cached.token;

  const response = await fetch(new URL('/api/v1/session/token', authDomain), {
    credentials: 'include',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ audience }),
  });
  if (!response.ok) throw new Error(response.status + ': ' + response.statusText);

  const result = await response.json();
  tokens.set(audience, { token: result.access_token, expiresAt: Date.now() + result.expires_in * 1000 });
  return result.access_token;
}

export async function authFetch(input, init = {}, { audience }) {
  const token = await getAccessToken(audience);
  const headers = new Headers(init.headers);
  headers.set('Authorization', 'Bearer ' + token);
  return fetch(input, { ...init, headers });
}

async function onload() {
  try {
    const profile = await getProfile();
    events.dispatchEvent(new CustomEvent('signin'));
    events.dispatchEvent(new CustomEvent('state', { detail: profile }));
  } catch {
    events.dispatchEvent(new CustomEvent('signout'));
    events.dispatchEvent(new CustomEvent('state', { detail: null }));
  }
}

if (['complete', 'interactive'].includes(document.readyState)) {
  onload();
} else {
  window.addEventListener('DOMContentLoaded', onload);
}
