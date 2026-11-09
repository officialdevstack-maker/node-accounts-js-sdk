import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JwksCache, verifyJwt } from '../src/jwt.js';
import { base64urlEncode } from '../src/util.js';

const enc = new TextEncoder();
const ISSUER = 'https://issuer.test/api/oidc';

async function sign(
  privateKey: CryptoKey,
  payload: object,
  header: object = { alg: 'RS256', typ: 'JWT', kid: 'k1' },
) {
  const head = base64urlEncode(enc.encode(JSON.stringify(header)));
  const body = base64urlEncode(enc.encode(JSON.stringify(payload)));
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, enc.encode(`${head}.${body}`)),
  );
  return `${head}.${body}.${base64urlEncode(signature)}`;
}

test('verifyJwt validates signature and standard claims', async () => {
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
    kid: 'k1',
    use: 'sig',
    alg: 'RS256',
  };
  const fetchKeys = (async () => new Response(JSON.stringify({ keys: [jwk] }))) as typeof fetch;
  const jwks = new JwksCache(async () => `${ISSUER}/jwks`, fetchKeys);
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, sub: '7', aud: 'client-a', exp: now + 60 };
  const token = await sign(pair.privateKey, claims);
  const options = { issuer: ISSUER, audience: 'client-a' };

  assert.equal((await verifyJwt(token, jwks, options)).payload.sub, '7');
  await assert.rejects(verifyJwt(token, jwks, { ...options, audience: 'client-b' }), /audience/);
  await assert.rejects(verifyJwt(token, jwks, { ...options, issuer: 'https://evil.test' }), /issuer/);

  const [head, , signature] = token.split('.');
  const forged = `${head}.${base64urlEncode(enc.encode(JSON.stringify({ ...claims, sub: '8' })))}.${signature}`;
  await assert.rejects(verifyJwt(forged, jwks, options), /signature/);

  const expired = await sign(pair.privateKey, { ...claims, exp: now - 3600 });
  await assert.rejects(verifyJwt(expired, jwks, options), /expired/);

  const none = await sign(pair.privateKey, claims, { alg: 'none', kid: 'k1' });
  await assert.rejects(verifyJwt(none, jwks, options), /algorithm/);
});
