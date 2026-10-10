import assert from 'node:assert/strict';
import { test } from 'node:test';
import { completePopupLogin, openLoginPopup, POPUP_MESSAGE_TYPE, POPUP_NONCE_PARAM } from '../assets/oidc.mjs';

async function withGlobals(values, callback) {
  const previous = new Map();
  for (const [key, value] of Object.entries(values)) {
    previous.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  try {
    return await callback();
  } finally {
    for (const [key, descriptor] of previous) {
      if (descriptor) {
        Object.defineProperty(globalThis, key, descriptor);
      } else {
        delete globalThis[key];
      }
    }
  }
}

function popupHarness(open = () => ({ closed: false, close() {} })) {
  const listeners = new Map();
  const removed = [];
  const opened = [];
  return {
    listeners,
    removed,
    opened,
    globals: {
      location: new URL('https://spa.example/'),
      crypto: { getRandomValues: (bytes) => bytes.fill(7) },
      open: (url, name, features) => {
        opened.push({ url, name, features });
        return open();
      },
      addEventListener: (type, listener) => listeners.set(type, listener),
      removeEventListener: (type, listener) => {
        removed.push(type);
        listeners.delete(type);
      },
    },
  };
}

test('popup helper adds a random nonce and accepts only the expected source, origin, and nonce', async () => {
  const popup = {
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const harness = popupHarness(() => popup);
  await withGlobals(harness.globals, async () => {
    const completion = openLoginPopup({
      loginUrl: 'https://rp.example/login',
      completionOrigin: 'https://rp.example',
      allowedOrigins: ['https://rp.example'],
    });
    const loginUrl = new URL(harness.opened[0].url);
    const nonce = loginUrl.searchParams.get(POPUP_NONCE_PARAM);
    assert.equal(nonce?.length, 64);
    assert.equal(harness.opened[0].name, 'oidc-login');

    const listener = harness.listeners.get('message');
    listener({
      origin: 'https://evil.example',
      source: popup,
      data: { type: POPUP_MESSAGE_TYPE, nonce, status: 'complete' },
    });
    listener({
      origin: 'https://rp.example',
      source: {},
      data: { type: POPUP_MESSAGE_TYPE, nonce, status: 'complete' },
    });
    listener({
      origin: 'https://rp.example',
      source: popup,
      data: { type: POPUP_MESSAGE_TYPE, nonce: 'wrong', status: 'complete' },
    });
    assert.equal(harness.listeners.has('message'), true);

    listener({
      origin: 'https://rp.example',
      source: popup,
      data: { type: POPUP_MESSAGE_TYPE, nonce, status: 'complete' },
    });
    await completion;
    assert.equal(popup.closed, true);
    assert.deepEqual(harness.removed, ['message']);
  });
});

test('popup helper reports blocked, closed, timed out, and RP-session failures', async () => {
  const blocked = popupHarness(() => null);
  await withGlobals(blocked.globals, async () => {
    await assert.rejects(
      openLoginPopup({
        loginUrl: 'https://rp.example/login',
        completionOrigin: 'https://rp.example',
        allowedOrigins: ['https://rp.example'],
      }),
      { code: 'POPUP_BLOCKED' },
    );
  });

  const closedPopup = {
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const closedHarness = popupHarness(() => closedPopup);
  await withGlobals(closedHarness.globals, async () => {
    const completion = openLoginPopup({
      loginUrl: 'https://rp.example/login',
      completionOrigin: 'https://rp.example',
      allowedOrigins: ['https://rp.example'],
      timeout: 2_000,
    });
    closedPopup.closed = true;
    await assert.rejects(completion, { code: 'POPUP_CLOSED' });
    assert.equal(closedHarness.listeners.has('message'), false);
    assert.equal(closedPopup.closed, true);
  });

  const timedOutPopup = {
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const timedOut = popupHarness(() => timedOutPopup);
  await withGlobals(timedOut.globals, async () => {
    await assert.rejects(
      openLoginPopup({
        loginUrl: 'https://rp.example/login',
        completionOrigin: 'https://rp.example',
        allowedOrigins: ['https://rp.example'],
        timeout: 5,
      }),
      { code: 'POPUP_TIMEOUT' },
    );
    assert.equal(timedOutPopup.closed, true);
    assert.equal(timedOut.listeners.has('message'), false);
  });

  const opener = { closed: false, postMessage() {} };
  let closed = false;
  let message;
  await withGlobals(
    {
      location: new URL('https://rp.example/callback'),
      opener: {
        ...opener,
        postMessage(data, targetOrigin) {
          message = { data, targetOrigin };
        },
      },
      close: () => (closed = true),
    },
    async () => {
      await assert.rejects(
        completePopupLogin({
          nonce: 'saved-popup-nonce',
          openerOrigin: 'https://spa.example',
          allowedOpenerOrigins: ['https://spa.example'],
          rpSessionCheck: async () => false,
        }),
        { code: 'RP_SESSION_NOT_ESTABLISHED' },
      );
      assert.deepEqual(message, {
        data: {
          type: POPUP_MESSAGE_TYPE,
          nonce: 'saved-popup-nonce',
          status: 'error',
          reason: 'rp-session-not-established',
        },
        targetOrigin: 'https://spa.example',
      });
      assert.equal(closed, true);
    },
  );
});

test('popup completion confirms the RP session and sends no credentials to the opener', async () => {
  let message;
  let closed = false;
  const opener = {
    closed: false,
    postMessage(data, targetOrigin) {
      message = { data, targetOrigin };
    },
  };
  await withGlobals(
    {
      location: new URL('https://rp.example/auth/popup-complete'),
      opener,
      close: () => (closed = true),
    },
    async () => {
      const result = await completePopupLogin({
        nonce: 'saved-popup-nonce',
        openerOrigin: 'https://spa.example',
        allowedOpenerOrigins: ['https://spa.example'],
        rpSessionCheck: async () => true,
      });
      assert.equal(result, true);
      assert.deepEqual(message, {
        data: { type: POPUP_MESSAGE_TYPE, nonce: 'saved-popup-nonce', status: 'complete' },
        targetOrigin: 'https://spa.example',
      });
      assert.equal(closed, true);
    },
  );
});
