import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createChallenge, createVerifier } from '../src/pkce.js';

test('S256 challenge matches the RFC 7636 appendix B vector', async () => {
  const challenge = await createChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
  assert.equal(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('verifier and challenge meet the server PKCE formats', async () => {
  const verifier = createVerifier();
  assert.match(verifier, /^[A-Za-z0-9\-._~]{43,128}$/);
  assert.match(await createChallenge(verifier), /^[A-Za-z0-9_-]{43}$/);
});
