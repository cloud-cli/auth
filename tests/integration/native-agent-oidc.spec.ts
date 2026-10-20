import { expect, test } from '@playwright/test';
import { createAgentFixture, deleteAgentFixture, signInAsAgent } from './agent-fixture.js';

test('native Agent OIDC clients use S256 PKCE and rotate refresh-token families', async ({ page }) => {
  test.skip(process.env.OIDC_INTEGRATION_ENABLED !== 'true', 'Requires a signing-enabled OIDC test instance');
  const fixture = await createAgentFixture(page);
  if (!fixture) {
    test.skip(true, 'Requires a deployment built with test fixture routes');
    return;
  }

  try {
    await signInAsAgent(page, fixture);
    const client = await page.evaluate(async () => {
      const response = await fetch('/api/v1/oidc/clients', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'Native Agent OIDC integration test',
          redirectUris: ['com.example.auth:/oauth2redirect'],
          postLogoutRedirectUris: ['com.example.auth:/signed-out'],
          scopes: ['profile', 'email'],
          isPublic: true,
        }),
      });
      if (!response.ok) throw new Error(`Could not create native OIDC client (${response.status}).`);
      return response.json();
    });

    const { authorizationUrl, verifier } = await page.evaluate((clientId) => {
      const codeVerifier = crypto.randomUUID().replaceAll('-', '').padEnd(43, 'a');
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier)).then((digest) => {
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const url = new URL('/authorize', location.origin);
        url.search = new URLSearchParams({
          response_type: 'code',
          client_id: clientId,
          redirect_uri: 'com.example.auth:/oauth2redirect',
          state: 'native_agent_state',
          scope: 'openid profile email offline_access',
          nonce: 'native_agent_nonce',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
        return { authorizationUrl: String(url), verifier: codeVerifier };
      });
    }, client.id);

    const authorization = await page.request.get(authorizationUrl, { maxRedirects: 0 });
    expect(authorization.status()).toBe(302);
    const callback = new URL(authorization.headers().location);
    expect(callback.protocol).toBe('com.example.auth:');
    expect(callback.searchParams.get('state')).toBe('native_agent_state');
    const code = callback.searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResponse = await page.request.post('/token', {
      form: {
        grant_type: 'authorization_code',
        client_id: client.id,
        code: code!,
        redirect_uri: 'com.example.auth:/oauth2redirect',
        code_verifier: verifier,
      },
    });
    expect(tokenResponse.status()).toBe(200);
    const tokens = await tokenResponse.json();
    expect(tokens.scope).toBe('openid profile email offline_access');
    expect(tokens.refresh_token).toBeTruthy();
    const claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());
    expect(claims.sub).toBe(fixture.agentId);
    expect(claims.nonce).toBe('native_agent_nonce');

    const userInfoResponse = await page.request.get('/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userInfoResponse.status()).toBe(200);
    expect((await userInfoResponse.json()).sub).toBe(fixture.agentId);

    const refreshResponse = await page.request.post('/token', {
      form: { grant_type: 'refresh_token', client_id: client.id, refresh_token: tokens.refresh_token },
    });
    expect(refreshResponse.status()).toBe(200);
    const refreshed = await refreshResponse.json();
    expect(refreshed.refresh_token).toBeTruthy();
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);

    const replayResponse = await page.request.post('/token', {
      form: { grant_type: 'refresh_token', client_id: client.id, refresh_token: tokens.refresh_token },
    });
    expect(replayResponse.status()).toBe(400);
    expect(await replayResponse.json()).toEqual({ error: 'invalid_grant' });
    const revokedFamilyResponse = await page.request.post('/token', {
      form: { grant_type: 'refresh_token', client_id: client.id, refresh_token: refreshed.refresh_token },
    });
    expect(revokedFamilyResponse.status()).toBe(400);

    const logout = new URL('/logout', page.url());
    logout.search = new URLSearchParams({
      client_id: client.id,
      id_token_hint: tokens.id_token,
      post_logout_redirect_uri: 'com.example.auth:/signed-out',
      state: 'native_agent_logout_state',
    });
    const logoutResponse = await page.request.get(String(logout), { maxRedirects: 0 });
    expect(logoutResponse.status()).toBe(302);
    const logoutCallback = new URL(logoutResponse.headers().location);
    expect(logoutCallback.protocol).toBe('com.example.auth:');
    expect(logoutCallback.searchParams.get('state')).toBe('native_agent_logout_state');
    expect((await page.request.get('/api/v1/profile')).status()).toBe(401);
  } finally {
    await deleteAgentFixture(page, fixture);
  }
});
