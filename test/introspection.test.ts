import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createVerifier } from '../src/server.js';
import { base64urlEncode } from '../src/util.js';

test('strict verification checks the signed access token with introspection', async () => {
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
  const jwk = {
    ...(await crypto.subtle.exportKey('jwk', pair.publicKey)),
    kid: 'introspection-key',
    use: 'sig',
    alg: 'RS256',
  };
  const now = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  const header = base64urlEncode(encoder.encode(JSON.stringify({
    alg: 'RS256',
    typ: 'at+jwt',
    kid: 'introspection-key',
  })));
  const body = base64urlEncode(encoder.encode(JSON.stringify({
    iss: issuer,
    sub: 'user-12',
    aud: 'client-a',
    client_id: 'client-a',
    gid: 21,
    scope: 'profile',
    exp: now + 60,
  })));
  const signingInput = `${header}.${body}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, encoder.encode(signingInput)),
  );
  const token = `${signingInput}.${base64urlEncode(signature)}`;
  let introspectionCalls = 0;
  const fetchFn: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/.well-known/openid-configuration')) {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        introspection_endpoint: `${issuer}/introspect`,
      });
    }
    if (url.endsWith('/jwks')) return Response.json({ keys: [jwk] });
    if (url.endsWith('/introspect')) {
      introspectionCalls++;
      assert.equal(new Headers(init?.headers).get('authorization'), `Basic ${btoa('api:secret')}`);
      assert.equal(new URLSearchParams(String(init?.body)).get('token'), token);
      return Response.json({
        active: true,
        sub: 'user-12',
        client_id: 'client-a',
        aud: 'client-a',
        exp: now + 60,
      });
    }
    return new Response(null, { status: 404 });
  };

  const verifier = createVerifier({
    issuer,
    audience: 'client-a',
    strict: true,
    introspectionClient: { clientId: 'api', clientSecret: 'secret' },
    fetch: fetchFn,
  });
  const verified = await verifier.verify(token);
  assert.equal(verified.sub, 'user-12');
  assert.equal(verified.principalType, 'user');
  assert.equal(introspectionCalls, 1);
});
