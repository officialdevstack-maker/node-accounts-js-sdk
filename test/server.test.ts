import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getBearerToken } from '../src/server.js';

test('getBearerToken accepts case-insensitive bearer schemes', () => {
  assert.equal(getBearerToken({ authorization: 'Bearer access-token' }), 'access-token');
  assert.equal(getBearerToken({ authorization: 'bearer access-token' }), 'access-token');
  assert.equal(getBearerToken({ authorization: ['Bearer access-token'] }), 'access-token');
  assert.equal(getBearerToken({ authorization: 'Basic credentials' }), null);
  assert.equal(getBearerToken({}), null);
});
