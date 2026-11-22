import assert from 'node:assert/strict';
import { test } from 'node:test';
import { openCookie, readCookie, sealCookie } from '../src/cookie-session.js';

test('cookie session sealing validates signature and expiry', async () => {
  const secret = 'test-session-secret';
  const sealed = await sealCookie({ sub: 'user-7' }, secret, 60);

  assert.equal((await openCookie<{ sub: string }>(sealed, secret))?.sub, 'user-7');
  assert.equal(await openCookie(sealed, `${secret}-wrong`), null);
  assert.equal(await openCookie(await sealCookie({ sub: 'user-7' }, secret, -1), secret), null);
});

test('readCookie decodes values and ignores malformed entries', () => {
  assert.equal(readCookie('theme=dark; spurs_app=hello%20world', 'spurs_app'), 'hello world');
  assert.equal(readCookie('spurs_app=%ZZ', 'spurs_app'), '%ZZ');
  assert.equal(readCookie('theme=dark', 'spurs_app'), undefined);
});

