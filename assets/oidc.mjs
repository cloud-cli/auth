export const POPUP_NONCE_PARAM = 'oidc_popup_nonce';
export const POPUP_MESSAGE_TYPE = 'oidc:login-complete';
const POPUP_TIMEOUT = 5 * 60_000;
const POPUP_CLOSE_POLL_INTERVAL = 250;

function popupError(code, message) {
  const error = new Error(message);
  error.name = 'OidcPopupError';
  error.code = code;
  return error;
}

function randomNonce() {
  if (!globalThis.crypto?.getRandomValues) {
    throw popupError('CRYPTO_UNAVAILABLE', 'Cryptographic randomness is unavailable.');
  }
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function parseUrl(value, name, base) {
  if (typeof value !== 'string' && !(value instanceof URL)) {
    throw new TypeError(`${name} must be a URL or URL string.`);
  }
  return new URL(value, base);
}

function originOf(value, name) {
  const url = parseUrl(value, name);
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError(`${name} must be an origin without a path, query, or fragment.`);
  }
  return url.origin;
}

function assertSecureOrigin(origin) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    throw popupError('INSECURE_ORIGIN', 'Popup sign-in origins must use HTTPS.');
  }
}

function allowedOriginSet(origins = []) {
  if (!Array.isArray(origins)) {
    throw new TypeError('allowedOrigins must be an array of exact origins.');
  }
  return new Set(origins.map((origin) => originOf(origin, 'allowed origin')));
}

function assertAllowed(origin, allowedOrigins) {
  assertSecureOrigin(origin);
  if (!allowedOrigins.has(origin)) {
    throw popupError('ORIGIN_NOT_ALLOWED', `Origin is not allowed: ${origin}`);
  }
}

function closeWindow(target) {
  try {
    target?.close();
  } catch {
    // The browser may have already closed or detached the popup.
  }
}

/** Open an RP-owned OIDC login flow in a popup and resolve after its RP session is confirmed. */
export function openLoginPopup({
  loginUrl,
  completionOrigin,
  allowedOrigins,
  timeout = POPUP_TIMEOUT,
  name = 'oidc-login',
  features = 'popup,width=520,height=720',
} = {}) {
  let popup;
  let nonce;
  let expectedCompletionOrigin;
  try {
    const allowed = allowedOriginSet(allowedOrigins);
    if (!globalThis.location?.href) {
      throw popupError('BROWSER_UNAVAILABLE', 'Popup sign-in requires a browser window.');
    }
    nonce = randomNonce();
    const resolvedLoginUrl = parseUrl(
      typeof loginUrl === 'function' ? loginUrl({ nonce }) : loginUrl,
      'loginUrl',
      globalThis.location.href,
    );
    expectedCompletionOrigin = originOf(completionOrigin, 'completionOrigin');
    assertAllowed(resolvedLoginUrl.origin, allowed);
    assertAllowed(expectedCompletionOrigin, allowed);
    resolvedLoginUrl.searchParams.set(POPUP_NONCE_PARAM, nonce);
    popup = globalThis.open?.(resolvedLoginUrl.href, name, features);
    if (!popup) {
      return Promise.reject(popupError('POPUP_BLOCKED', 'The sign-in popup was blocked.'));
    }
  } catch (error) {
    closeWindow(popup);
    return Promise.reject(error);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let timeoutTimer;
    let closePoll;

    const cleanup = () => {
      clearTimeout(timeoutTimer);
      clearInterval(closePoll);
      globalThis.removeEventListener?.('message', onMessage);
    };

    const finish = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      closeWindow(popup);
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };

    const onMessage = (event) => {
      if (event.origin !== expectedCompletionOrigin || event.source !== popup) {
        return;
      }
      const message = event.data;
      if (!message || message.type !== POPUP_MESSAGE_TYPE || message.nonce !== nonce) {
        return;
      }
      if (message.status === 'complete') {
        finish();
      } else if (message.status === 'error') {
        const code = message.reason === 'rp-session-not-established' ? 'RP_SESSION_NOT_ESTABLISHED' : 'RP_LOGIN_FAILED';
        finish(popupError(code, 'The relying-party session was not established.'));
      }
    };

    globalThis.addEventListener?.('message', onMessage);
    timeoutTimer = setTimeout(
      () => finish(popupError('POPUP_TIMEOUT', 'The sign-in popup timed out.')),
      Math.max(1, timeout),
    );
    closePoll = setInterval(() => {
      if (popup.closed) {
        finish(popupError('POPUP_CLOSED', 'The sign-in popup closed before completing login.'));
      }
    }, POPUP_CLOSE_POLL_INTERVAL);
  });
}

async function checkRelyingPartySession(rpSessionCheck, completionOrigin) {
  if (typeof rpSessionCheck === 'function') {
    const result = await rpSessionCheck();
    if (typeof result === 'boolean') {
      return result;
    }
    if (result && typeof result.ok === 'boolean') {
      if (result.ok) {
        return true;
      }
      if (result.status === 401) {
        return false;
      }
      throw popupError('RP_SESSION_CHECK_FAILED', 'The relying-party session check failed.');
    }
    throw new TypeError('rpSessionCheck must return a boolean or Response.');
  }

  const url = parseUrl(rpSessionCheck, 'rpSessionCheck', `${completionOrigin}/`);
  if (url.origin !== completionOrigin) {
    throw popupError('INVALID_SESSION_CHECK_ORIGIN', 'rpSessionCheck must use the completion origin.');
  }
  const response = await fetch(url, { credentials: 'include', cache: 'no-store' });
  if (response.ok) {
    return true;
  }
  if (response.status === 401) {
    return false;
  }
  throw popupError('RP_SESSION_CHECK_FAILED', 'The relying-party session check failed.');
}

/** Confirm the RP session from its callback page, notify the opener without credentials, and close. */
export async function completePopupLogin({
  nonce,
  openerOrigin,
  allowedOpenerOrigins,
  completionOrigin = globalThis.location?.origin,
  rpSessionCheck,
} = {}) {
  const actualOrigin = globalThis.location?.origin;
  if (!nonce || typeof nonce !== 'string') {
    throw popupError('INVALID_NONCE', 'A popup nonce from the validated RP login transaction is required.');
  }
  if (!actualOrigin || originOf(completionOrigin, 'completionOrigin') !== actualOrigin) {
    throw popupError('INVALID_COMPLETION_ORIGIN', 'The popup completion page is not on the configured RP origin.');
  }
  assertSecureOrigin(actualOrigin);
  const allowed = allowedOriginSet(allowedOpenerOrigins);
  const targetOrigin = originOf(openerOrigin, 'openerOrigin');
  assertAllowed(targetOrigin, allowed);
  const opener = globalThis.opener;
  if (!opener || opener.closed) {
    closeWindow(globalThis);
    throw popupError('OPENER_UNAVAILABLE', 'The popup opener is no longer available.');
  }

  const send = (status, reason) => {
    opener.postMessage({ type: POPUP_MESSAGE_TYPE, nonce, status, ...(reason ? { reason } : {}) }, targetOrigin);
    closeWindow(globalThis);
  };

  try {
    if (!rpSessionCheck) {
      throw new TypeError('rpSessionCheck is required to confirm the relying-party session.');
    }
    if (await checkRelyingPartySession(rpSessionCheck, actualOrigin)) {
      send('complete');
      return true;
    }
    send('error', 'rp-session-not-established');
    throw popupError('RP_SESSION_NOT_ESTABLISHED', 'The relying-party session was not established.');
  } catch (error) {
    if (error.code === 'RP_SESSION_NOT_ESTABLISHED') {
      throw error;
    }
    send('error', 'rp-session-check-failed');
    throw error.code
      ? error
      : popupError('RP_SESSION_CHECK_FAILED', 'The relying-party session could not be confirmed.');
  }
}
