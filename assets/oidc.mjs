const DEFAULT_HEARTBEAT_INTERVAL = 60_000;
const DEFAULT_HIDDEN_INTERVAL = 5 * 60_000;
const DEFAULT_POPUP_TIMEOUT = 5 * 60_000;

function createError(message, code, status) {
  const error = new Error(message);
  error.name = 'OidcClientError';
  error.code = code;
  if (status !== undefined) {
    error.status = status;
  }
  return error;
}

function randomNonce() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function resolveRpUrl(value, nonce) {
  const result = typeof value === 'function' ? value({ nonce }) : value;
  if (typeof result !== 'string' && !(result instanceof URL)) {
    throw new TypeError('A relying-party URL or URL builder is required.');
  }
  return new URL(result, globalThis.location?.href);
}

/** Create a framework-independent browser OIDC session client. */
export function createOidcClient(options) {
  if (!options || typeof options.issuer !== 'string') {
    throw new TypeError('An Auth issuer URL is required.');
  }

  const issuer = new URL(options.issuer);
  const allowedOrigins = new Set((options.allowedOrigins || []).map((origin) => new URL(origin).origin));
  const heartbeatInterval = Math.max(5_000, options.heartbeatInterval ?? DEFAULT_HEARTBEAT_INTERVAL);
  const hiddenInterval = Math.max(heartbeatInterval, options.hiddenInterval ?? DEFAULT_HIDDEN_INTERVAL);
  const fetcher = options.fetch || globalThis.fetch.bind(globalThis);
  const listeners = new Map();
  const tokens = new Map();
  let state = { status: 'unknown', authenticated: false, relyingPartySession: 'unknown', reason: 'initial' };
  let started = false;
  let timer;
  let checkPromise;
  let popupAttempt;
  const onOnline = () => recheck('online');
  const onFocus = () => recheck('focus');

  function emit(type, detail) {
    for (const listener of listeners.get(type) || []) {
      listener({ type, detail, target: api });
    }
  }

  function setState(patch, reason) {
    const next = { ...state, ...patch, reason };
    if (Object.keys(next).some((key) => next[key] !== state[key])) {
      state = next;
      emit('statechange', { ...state });
    }
  }

  function reportError(error, operation) {
    emit('error', { error, operation });
  }

  function ensureAllowedUrl(url) {
    if (!allowedOrigins.has(url.origin)) {
      throw createError(`Relying-party origin is not allowed: ${url.origin}`, 'ORIGIN_NOT_ALLOWED');
    }
    if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      throw createError('Relying-party URLs must use HTTPS.', 'INSECURE_URL');
    }
  }

  async function checkRelyingPartySession() {
    if (!options.rpSessionCheck) {
      return 'unknown';
    }
    try {
      const response =
        typeof options.rpSessionCheck === 'function'
          ? await options.rpSessionCheck()
          : await fetcher(new URL(options.rpSessionCheck, globalThis.location?.href), { credentials: 'include' });
      if (typeof response === 'boolean') {
        return response ? 'authenticated' : 'unauthenticated';
      }
      if (response && typeof response.ok === 'boolean') {
        return response.ok ? 'authenticated' : response.status === 401 ? 'unauthenticated' : 'unavailable';
      }
      throw new TypeError('The relying-party session check must return a boolean or Response.');
    } catch (error) {
      reportError(error, 'relying-party-session-check');
      return 'unavailable';
    }
  }

  async function checkSession(reason = 'heartbeat') {
    if (checkPromise) {
      return checkPromise;
    }
    checkPromise = (async () => {
      try {
        const response = await fetcher(new URL('/api/v1/profile', issuer), {
          method: 'HEAD',
          credentials: 'include',
          mode: 'cors',
          cache: 'no-store',
        });
        if (response.status === 401) {
          setState({ status: 'unauthenticated', authenticated: false }, reason);
          return false;
        }
        if (!response.ok) {
          if (response.status >= 500) {
            reportError(
              createError(
                `Auth session check failed with HTTP ${response.status}.`,
                'SESSION_CHECK_FAILED',
                response.status,
              ),
              'session-check',
            );
            setState({ status: 'unavailable' }, reason);
            return null;
          }
          const error = createError(
            `Auth session check failed with HTTP ${response.status}.`,
            'SESSION_CHECK_FAILED',
            response.status,
          );
          reportError(error, 'session-check');
          setState({ status: 'unavailable' }, reason);
          return null;
        }
        const rpStatus = await checkRelyingPartySession();
        setState({ status: 'authenticated', authenticated: true, relyingPartySession: rpStatus }, reason);
        return true;
      } catch (error) {
        reportError(error, 'session-check');
        setState({ status: 'unavailable' }, reason);
        return null;
      } finally {
        checkPromise = undefined;
      }
    })();
    return checkPromise;
  }

  function schedule() {
    clearTimeout(timer);
    if (!started) {
      return;
    }
    const delay = globalThis.document?.visibilityState === 'hidden' ? hiddenInterval : heartbeatInterval;
    timer = setTimeout(async () => {
      if (globalThis.document?.visibilityState !== 'hidden') {
        await checkSession('heartbeat');
      }
      schedule();
    }, delay);
  }

  function recheck(reason) {
    if (started) {
      void checkSession(reason).finally(schedule);
    }
  }

  function onVisibility() {
    if (globalThis.document?.visibilityState === 'visible') {
      recheck('visibility');
    } else {
      schedule();
    }
  }

  function onMessage(event) {
    const attempt = popupAttempt;
    if (!attempt || event.origin !== attempt.origin || event.source !== attempt.popup) {
      return;
    }
    const data = event.data;
    if (!data || data.type !== attempt.messageType || data.nonce !== attempt.nonce) {
      return;
    }
    if (data.status !== 'complete') {
      finishPopup(createError('Relying-party login did not complete.', 'CALLBACK_FAILED'));
      return;
    }
    void (async () => {
      await checkSession('popup-sign-in');
      if (state.status === 'authenticated' && state.relyingPartySession === 'authenticated') {
        finishPopup(null, { ...state });
      } else if (state.status === 'authenticated') {
        finishPopup(createError('The relying-party session was not confirmed.', 'RP_SESSION_NOT_CONFIRMED'));
      } else {
        finishPopup(createError('The Auth session was not confirmed after sign-in.', 'AUTH_SESSION_NOT_CONFIRMED'));
      }
    })().catch((error) => finishPopup(error));
  }

  function finishPopup(error, result) {
    const attempt = popupAttempt;
    if (!attempt) {
      return;
    }
    popupAttempt = undefined;
    clearInterval(attempt.closePoll);
    clearTimeout(attempt.timeout);
    globalThis.removeEventListener('message', onMessage);
    if (error) {
      reportError(error, 'popup-sign-in');
      attempt.reject(error);
    } else {
      attempt.resolve(result);
    }
  }

  function start() {
    if (started) {
      return api;
    }
    started = true;
    globalThis.addEventListener?.('online', onOnline);
    globalThis.addEventListener?.('focus', onFocus);
    globalThis.addEventListener?.('message', onMessage);
    globalThis.document?.addEventListener('visibilitychange', onVisibility);
    void checkSession('start').finally(schedule);
    schedule();
    return api;
  }

  function stop() {
    started = false;
    clearTimeout(timer);
    if (popupAttempt) {
      const popup = popupAttempt.popup;
      finishPopup(createError('Client stopped during popup sign-in.', 'CLIENT_STOPPED'));
      try {
        popup.close();
      } catch {
        // Popup may already be closed.
      }
    }
    tokens.clear();
    globalThis.removeEventListener?.('online', onOnline);
    globalThis.removeEventListener?.('focus', onFocus);
    globalThis.removeEventListener?.('message', onMessage);
    globalThis.document?.removeEventListener('visibilitychange', onVisibility);
    return api;
  }

  async function getAccessToken(audience) {
    if (typeof audience !== 'string' || audience.length === 0) {
      throw new TypeError('A token audience is required.');
    }
    const cached = tokens.get(audience);
    if (cached?.expiresAt > Date.now() + 30_000) {
      return cached.token;
    }
    if (cached?.promise) {
      return cached.promise;
    }
    const entry = {};
    entry.promise = (async () => {
      try {
        const response = await fetcher(new URL('/api/v1/session/token', issuer), {
          method: 'POST',
          credentials: 'include',
          mode: 'cors',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ audience }),
        });
        if (response.status === 401) {
          tokens.delete(audience);
          setState({ status: 'unauthenticated', authenticated: false }, 'token-unauthorized');
          throw createError('The Auth session has expired.', 'UNAUTHENTICATED', 401);
        }
        if (response.status === 403 || response.status === 400 || response.status === 503) {
          throw createError(
            `Token request is not configured for this client or audience (HTTP ${response.status}).`,
            'TOKEN_CONFIGURATION_ERROR',
            response.status,
          );
        }
        if (!response.ok) {
          throw createError(
            `Token request failed with HTTP ${response.status}.`,
            'TOKEN_REQUEST_FAILED',
            response.status,
          );
        }
        const result = await response.json();
        if (typeof result.access_token !== 'string' || !Number.isFinite(result.expires_in)) {
          throw createError('Auth returned an invalid access-token response.', 'INVALID_TOKEN_RESPONSE');
        }
        entry.token = result.access_token;
        entry.expiresAt = Date.now() + result.expires_in * 1000;
        return entry.token;
      } catch (error) {
        if (error.code !== 'UNAUTHENTICATED') {
          reportError(error, 'get-access-token');
        }
        throw error;
      } finally {
        if (tokens.get(audience) === entry) {
          if (entry.token) {
            delete entry.promise;
          } else {
            tokens.delete(audience);
          }
        }
      }
    })();
    tokens.set(audience, entry);
    return entry.promise;
  }

  function signInWithPopup(config) {
    if (popupAttempt) {
      return Promise.reject(createError('A popup sign-in is already active.', 'POPUP_ALREADY_ACTIVE'));
    }
    if (!config || !config.loginUrl) {
      return Promise.reject(new TypeError('A relying-party login URL or builder is required.'));
    }
    const nonce = randomNonce();
    let loginUrl;
    try {
      loginUrl = resolveRpUrl(config.loginUrl, nonce);
      ensureAllowedUrl(loginUrl);
    } catch (error) {
      return Promise.reject(error);
    }
    loginUrl.searchParams.set(config.nonceParam || 'oidc_popup_nonce', nonce);
    const popup = globalThis.open(
      loginUrl.href,
      config.name || 'oidc-sign-in',
      config.features || 'popup,width=520,height=720',
    );
    if (!popup) {
      return Promise.reject(createError('The sign-in popup was blocked.', 'POPUP_BLOCKED'));
    }
    let completionUrl;
    try {
      completionUrl = resolveRpUrl(config.completionUrl, nonce);
      ensureAllowedUrl(completionUrl);
    } catch (error) {
      popup.close();
      return Promise.reject(error);
    }
    const timeoutMs = config.timeout ?? DEFAULT_POPUP_TIMEOUT;
    return new Promise((resolve, reject) => {
      const attempt = {
        popup,
        origin: completionUrl.origin,
        nonce,
        messageType: config.messageType || 'oidc:login-complete',
        resolve,
        reject,
      };
      attempt.timeout = setTimeout(
        () => finishPopup(createError('Popup sign-in timed out.', 'POPUP_TIMEOUT')),
        timeoutMs,
      );
      attempt.closePoll = setInterval(() => {
        if (popup.closed) {
          finishPopup(createError('The sign-in popup was closed before completion.', 'POPUP_CLOSED'));
        }
      }, 500);
      popupAttempt = attempt;
      globalThis.addEventListener?.('message', onMessage);
    });
  }

  const api = {
    start,
    stop,
    getState: () => ({ ...state }),
    isAuthenticated: () => state.status === 'authenticated' && state.authenticated,
    getAccessToken,
    signInWithPopup,
    addEventListener(type, listener) {
      if (!listeners.has(type)) {
        listeners.set(type, new Set());
      }
      listeners.get(type).add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
  };
  return api;
}
