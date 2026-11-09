import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SpursAuth } from '../src/client.js';
import { MemoryStorage } from '../src/storage.js';
import { base64urlEncode } from '../src/util.js';

const issuer = 'https://issuer.test/api/oidc';
const encoder = new TextEncoder();

async function sign(privateKey: CryptoKey, payload: object): Promise<string> {
  const header = base64urlEncode(encoder.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test-key' })));
  const body = base64urlEncode(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${header}.${body}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, encoder.encode(signingInput)),
  );
  return `${signingInput}.${base64urlEncode(signature)}`;
}

test('authorization request and code exchange verify the ID token', async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const jwk = {
    ...(await crypto.subtle.exportKey('jwk', pair.publicKey)),
    kid: 'test-key',
    use: 'sig',
    alg: 'RS256',
  };
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  let nonce = '';
  const fetchFn: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/.well-known/openid-configuration')) {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (url.endsWith('/jwks')) return Response.json({ keys: [jwk] });
    if (url.endsWith('/token')) {
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get('grant_type'), 'authorization_code');
      assert.equal(body.get('client_id'), 'client-a');
      const idToken = await sign(pair.privateKey, {
        iss: issuer,
        sub: 'user-7',
        aud: 'client-a',
        exp: Math.floor(Date.now() / 1000) + 60,
        nonce,
      });
      return Response.json({
        access_token: 'access-token',
        token_type: 'Bearer',
        expires_in: 600,
        scope: 'openid profile',
        id_token: idToken,
      });
    }
    if (url.endsWith('/userinfo')) {
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer access-token');
      return Response.json({ sub: 'user-7', name: 'User Seven' });
    }
    return new Response(null, { status: 404 });
  };

  const auth = new SpursAuth({
    issuer,
    clientId: 'client-a',
    redirectUri: 'https://app.test/callback',
    storage: 'memory',
    fetch: fetchFn,
  });
  const request = await auth.createAuthorizationRequest();
  const authorizationUrl = new URL(request.url);
  nonce = request.nonce;

  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorizationUrl.searchParams.get('scope'), 'openid profile email');

  const tokens = await auth.exchangeCode(
    new URLSearchParams({
      code: 'authorization-code',
      state: request.state,
      iss: issuer,
    }),
    {
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
      redirectUri: request.redirectUri,
    },
  );
  assert.equal(tokens.claims?.sub, 'user-7');
  assert.equal(tokens.claims?.nonce, request.nonce);
  assert.deepEqual(await auth.userinfo(tokens.accessToken), { sub: 'user-7', name: 'User Seven' });
  assert.equal(calls.filter((call) => call.url.endsWith('/jwks')).length, 1);
  auth.dispose();
});

test('fetch retries once after a 401 and persists the rotated refresh token', async () => {
  const storage = new MemoryStorage();
  storage.setItem('spurs:client-a:session', JSON.stringify({
    accessToken: 'old-access-token',
    tokenType: 'Bearer',
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    scope: ['openid'],
    refreshToken: 'old-refresh-token',
  }));
  const resourceAuthorizations: string[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith('/.well-known/openid-configuration')) {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
      });
    }
    if (url.endsWith('/token')) {
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get('grant_type'), 'refresh_token');
      assert.equal(body.get('refresh_token'), 'old-refresh-token');
      return Response.json({
        access_token: 'new-access-token',
        token_type: 'Bearer',
        expires_in: 600,
        scope: 'openid',
        refresh_token: 'new-refresh-token',
      });
    }
    if (url === 'https://api.test/me') {
      resourceAuthorizations.push(new Headers(input instanceof Request ? input.headers : init?.headers).get('authorization') ?? '');
      return resourceAuthorizations.length === 1
        ? new Response(null, { status: 401 })
        : new Response('ok', { status: 200 });
    }
    return new Response(null, { status: 404 });
  };
  const auth = new SpursAuth({
    issuer,
    clientId: 'client-a',
    redirectUri: 'https://app.test/callback',
    storage,
    fetch: fetchFn,
  });

  const response = await auth.fetch('https://api.test/me', { method: 'GET' });
  assert.equal(response.status, 200);
  assert.deepEqual(resourceAuthorizations, ['Bearer old-access-token', 'Bearer new-access-token']);
  assert.equal(auth.getTokens()?.refreshToken, 'new-refresh-token');
  auth.dispose();
});
