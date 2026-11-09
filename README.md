# @spurs/auth

JavaScript SDK for Spurs Accounts using OpenID Connect authorization code flow with PKCE. It has no runtime dependencies and supports browsers and Node.js 20+.

## Install locally

```sh
cd sdk/js
npm install
npm run build
cd ../../frontend
npm install ../sdk/js
```

Register the app with Spurs before using it:

```sh
npm run artisan -- oidc:client:create "VendPro" --first-party --public \
  --redirect=http://localhost:5174/callback --logout-redirect=http://localhost:5174 \
  --scopes=openid,profile,email,phone,offline_access
```

## Browser app

```ts
import { SpursAuth } from '@spurs/auth';

export const auth = new SpursAuth({
  issuer: 'http://localhost:8080/api/oidc',
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: location.origin,
  scope: 'openid profile email',
  // offlineAccess: true, // Request offline_access for third-party apps.
  // storage: 'memory',   // Or 'session' (default) or 'local'.
});
```

Start sign-in and finish it on the registered callback route:

```ts
await auth.signIn({ returnTo: '/dashboard' });

const { user, returnTo } = await auth.handleRedirectCallback();
navigate(returnTo, { replace: true });
```

`signIn()` stores the PKCE verifier, state, and nonce in session storage. `handleRedirectCallback()` validates state and issuer, exchanges the code, verifies the ID token, stores the session, and by default removes callback parameters from the address bar.

```ts
auth.getUser();                       // Verified ID-token claims.
auth.isAuthenticated();
await auth.getAccessToken();          // Refreshes before expiry.
await auth.fetch('/api/wallet');      // Adds Bearer auth and retries once after a 401.
await auth.fetchUserInfo();           // Fetches current profile from /userinfo.
auth.onChange((tokens) => { /* session changes */ });

await auth.signOut();                 // Signs out of this app and revokes its refresh token.
await auth.signOutEverywhere();       // Also ends the Spurs browser session.
```

For browser apps, never set `clientSecret`: a browser cannot keep it confidential. Third-party browser apps need their origin listed in the backend's `CORS_ORIGINS` setting in production.

## API server

Import the verifier from `@spurs/auth/server`. It verifies RS256 access tokens, issuer, audience, expiry, and the `at+jwt` token type without requiring Express as a dependency:

```ts
import express from 'express';
import { createVerifier } from '@spurs/auth/server';
import type { VerifiedToken } from '@spurs/auth/server';

declare global {
  namespace Express {
    interface Request {
      spurs?: VerifiedToken;
    }
  }
}

const spurs = createVerifier({
  issuer: process.env.SPURS_ISSUER!,
  audience: process.env.SPURS_CLIENT_ID!,
  // strict: true, // Also check /userinfo so revoked grants stop working immediately.
});

const app = express();
app.get('/api/me', spurs.middleware({ scopes: ['profile'] }), (req, res) => {
  res.json({ userId: req.spurs?.sub, scopes: req.spurs?.scopes });
});
```

With `strict: true`, network or provider failures are passed to Express's error handler; invalid/revoked tokens are rejected as unauthorized.

## Server-side web apps

For confidential clients, keep the state, nonce, and verifier in your own server-side session:

```ts
const auth = new SpursAuth({ issuer, clientId, clientSecret, redirectUri });

const request = await auth.createAuthorizationRequest();
session.oidc = {
  state: request.state,
  nonce: request.nonce,
  codeVerifier: request.codeVerifier,
};
res.redirect(request.url);

const tokens = await auth.exchangeCode(new URL(req.url, origin), session.oidc);
```

## Refresh-token storage

The default `session` storage is scoped to a tab. `memory` avoids persistent browser storage; `local` shares the rotated token set between tabs, but persists it across browser restarts. Web Locks serialize refresh requests when available; use a shared store such as `local` when multiple tabs need to share a refresh token.

## Errors

SDK failures throw `SpursAuthError` with a `code`, such as server errors (`invalid_grant`, `login_required`, `consent_required`, `access_denied`) or SDK errors (`state_mismatch`, `issuer_mismatch`, `nonce_mismatch`, `invalid_token`, `not_authenticated`, `no_refresh_token`, `network_error`).

## Development

```sh
npm run typecheck
npm test
npm run build
```

No React bindings, device flow, or client-credentials grant are included.
