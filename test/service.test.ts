import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServiceClient } from '../src/service.js';

test('service client caches credentials and retries one unauthorized request', async () => {
  const tokenAuthorizations: string[] = [];
  const resourceAuthorizations: string[] = [];
  let tokenRequests = 0;
  const fetchFn: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/token')) {
      tokenAuthorizations.push(new Headers(init?.headers).get('authorization') ?? '');
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get('grant_type'), 'client_credentials');
      assert.equal(body.get('scope'), 'users:read');
      tokenRequests++;
      return Response.json({
        access_token: `service-token-${tokenRequests}`,
        token_type: 'Bearer',
        expires_in: 3600,
      });
    }

    const authorization = new Headers(init?.headers).get('authorization') ?? '';
    resourceAuthorizations.push(authorization);
    return authorization === 'Bearer service-token-1'
      ? new Response(null, { status: 401 })
      : new Response('ok', { status: 200 });
  };

  const service = createServiceClient({
    issuer: 'https://issuer.test/api/oidc/',
    clientId: 'service-a',
    clientSecret: 'secret-a',
    scope: 'users:read',
    fetch: fetchFn,
  });

  const [first, second] = await Promise.all([
    service.fetch('https://api.test/api/internal/users/1', { headers: { 'X-Request': 'one' } }),
    service.fetch('https://api.test/api/internal/users/2'),
  ]);

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(tokenRequests, 2);
  assert.deepEqual(tokenAuthorizations, [`Basic ${btoa('service-a:secret-a')}`, `Basic ${btoa('service-a:secret-a')}`]);
  assert.deepEqual(resourceAuthorizations.sort(), [
    'Bearer service-token-1',
    'Bearer service-token-1',
    'Bearer service-token-2',
    'Bearer service-token-2',
  ]);
  assert.equal(await service.getToken(), 'service-token-2');
});
