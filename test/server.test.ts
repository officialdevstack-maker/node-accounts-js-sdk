import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createVerifier, getBearerToken, type RequestLike, type ResponseLike } from '../src/server.js';
import { base64urlEncode } from '../src/util.js';

test('getBearerToken accepts case-insensitive bearer schemes', () => {
  assert.equal(getBearerToken({ authorization: 'Bearer access-token' }), 'access-token');
  assert.equal(getBearerToken({ authorization: 'bearer access-token' }), 'access-token');
  assert.equal(getBearerToken({ authorization: ['Bearer access-token'] }), 'access-token');
  assert.equal(getBearerToken({ authorization: 'Basic credentials' }), null);
  assert.equal(getBearerToken({}), null);
});

test('createVerifier checks access-token claims and middleware scopes', async () => {
  const issuer = 'https://issuer.test/api/oidc';
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
  const publicJwk = {
    ...(await crypto.subtle.exportKey('jwk', pair.publicKey)),
    kid: 'access-key',
    use: 'sig',
    alg: 'RS256',
  };
  const encoder = new TextEncoder();
  const header = base64urlEncode(encoder.encode(JSON.stringify({
    alg: 'RS256',
    typ: 'at+jwt',
    kid: 'access-key',
  })));
  const payload = base64urlEncode(encoder.encode(JSON.stringify({
    iss: issuer,
    sub: 'user-7',
    aud: 'client-a',
    client_id: 'client-a',
    gid: 17,
    scope: 'openid profile',
    exp: Math.floor(Date.now() / 1000) + 60,
  })));
  const signingInput = `${header}.${payload}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, encoder.encode(signingInput)),
  );
  const token = `${signingInput}.${base64urlEncode(signature)}`;
  const fetchFn: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/.well-known/openid-configuration')) {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
      });
    }
    if (url.endsWith('/jwks')) return Response.json({ keys: [publicJwk] });
    if (url.endsWith('/userinfo')) {
      assert.equal(new Headers(init?.headers).get('authorization'), `Bearer ${token}`);
      return Response.json({ sub: 'user-7' });
    }
    return new Response(null, { status: 404 });
  };

  const verifier = createVerifier({
    issuer,
    audience: 'client-a',
    fetch: fetchFn,
  });
  assert.equal((await verifier.verify(token)).grantId, 17);

  let status = 0;
  const responseHeaders: Record<string, string> = {};
  const responseBody: unknown[] = [];
  const response: ResponseLike = {
    status(code) {
      status = code;
      return this;
    },
    setHeader(name, value) {
      responseHeaders[name] = value;
    },
    json(body) {
      responseBody.push(body);
    },
  };
  const request: RequestLike = { headers: { authorization: `Bearer ${token}` } };
  let nextCalled = false;
  await verifier.middleware({ scopes: ['email'] })(request, response, () => {
    nextCalled = true;
  });

  assert.equal(status, 403);
  assert.equal(responseHeaders['WWW-Authenticate'], 'Bearer error="insufficient_scope", scope="email"');
  assert.equal(responseBody.length, 1);
  assert.equal(nextCalled, false);

  await verifier.middleware({ scopes: ['profile'] })(request, response, () => {
    nextCalled = true;
  });
  assert.equal(nextCalled, true);
  assert.equal(request.spurs?.sub, 'user-7');
});
