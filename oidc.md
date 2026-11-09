# Spurs Accounts: OpenID Connect

Spurs Accounts is an OpenID Connect (OIDC) provider. It lets apps sign users in with their Spurs account and lets Spurs' own backend services talk to each other securely.

| Use case | Who | Grant | Section |
|---|---|---|---|
| Sign users in to a Spurs app | First-party apps (VendPro, AjoSave, ...) | Authorization code + PKCE | [User sign-in](#2-user-sign-in-authorization-code--pkce) |
| Sign users in to an outside app | Third-party apps | Authorization code + PKCE, with consent | [Third-party apps](#6-third-party-apps) |
| Service calls service | Spurs backends | Client credentials | [Spurs to Spurs](#7-spurs-to-spurs-service-authentication) |

> **Status note.** Sections 1 to 6 describe code that exists in the repo today. Section 7 (client credentials), the introspection endpoint, key rotation and the `oidc:client:create` command are additions proposed in the same working session. Check each against your tree before relying on it. They are marked **(added)**.

---

## 1. Concepts

- **Issuer**: the base URL of the provider, `OIDC_ISSUER` (default `${APP_URL}/api/oidc`). It must match the `iss` claim in every token exactly.
- **Client**: an app registered in `oauth_clients`, identified by `client_id`.
- **Grant**: a user's approval of a client (`oauth_grants`). One row per user and client. Deleting it ("Connected apps" screen) removes the app's access.
- **Access token**: short-lived RS256 JWT sent as `Authorization: Bearer ...`.
- **ID token**: RS256 JWT proving who signed in. Meant for the client, never for APIs.
- **Refresh token**: opaque random string, single use, rotated on every refresh.

### Client types

| Type | Consent screen | Refresh token | Typical use |
|---|---|---|---|
| `first_party` | Skipped | Always issued | Your own apps and services |
| `third_party` | Required once per scope set | Only with `offline_access` | Outside developers |

A client is **confidential** when it has a secret (server-side apps, services) and **public** when it does not (SPAs, mobile). Public clients rely on PKCE alone.

---

## 2. User sign-in (authorization code + PKCE)

```
 Browser/App                 Spurs API                     Spurs Frontend
     |  GET /authorize ------->|                                  |
     |                         | not signed in?                   |
     |<-- 302 /login?return_to=|--------------------------------->|
     |  (user signs in, comes back to /authorize)                 |
     |                         | needs consent? (third-party)     |
     |<-- 302 /consent?request=|--------------------------------->|
     |  GET/POST /consent ---->|                                  |
     |<-- 302 redirect_uri?code=...&state=...&iss=...             |
     |  POST /token (code + code_verifier) ->|                    |
     |<-- access_token, id_token, refresh_token                    |
```

1. The app generates `state`, `nonce` and a PKCE `code_verifier`, then sends the browser to `/authorize`.
2. If there is no Spurs session, the user is redirected to the frontend `/login`. `return_to` carries the original `/authorize` URL.
3. If consent is needed, the user is redirected to `/consent?request=<signed token>`. The token is an HS256 JWT signed with `JWT_SECRET`, valid for `OIDC_REQUEST_TTL`, so the frontend cannot tamper with the request.
4. The server issues a single-use authorization code (`OIDC_CODE_TTL`, 60 s) and redirects to the client's `redirect_uri`.
5. The app exchanges the code at `/token` with the `code_verifier`.

### Authorization request

`GET /api/oidc/authorize`

| Parameter | Required | Notes |
|---|---|---|
| `client_id` | yes | Must be registered and active |
| `redirect_uri` | yes | Exact match against the client's registered URIs |
| `response_type` | yes | Only `code` |
| `scope` | yes | Must include `openid`. Every scope must be allowed for the client |
| `code_challenge` | yes | `base64url(sha256(verifier))`, 43 characters |
| `code_challenge_method` | yes | Only `S256` |
| `state` | recommended | Returned unchanged. Verify it |
| `nonce` | recommended | Echoed in the ID token. Verify it |
| `prompt` | no | `none` (never show UI) or `consent` (always ask) |

Errors that cannot be trusted to a redirect (unknown client, bad `redirect_uri`) go to the frontend at `/oauth/error`. All other errors are returned to the client's `redirect_uri` as `?error=...&error_description=...&state=...&iss=...`.

### Token request

`POST /api/oidc/token` (`application/x-www-form-urlencoded`)

Authorization code:

```
grant_type=authorization_code
code=...
redirect_uri=...            (must equal the authorize request)
code_verifier=...           (43 to 128 URL-safe characters)
client_id=...               (public clients, or use Basic auth)
```

Refresh:

```
grant_type=refresh_token
refresh_token=...
scope=...                   (optional, may only narrow)
```

Client authentication, in order of preference:

- `client_secret_basic`: `Authorization: Basic base64(urlencode(id):urlencode(secret))`
- `client_secret_post`: `client_id` and `client_secret` in the body
- `none`: public clients (PKCE only)

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "openid profile email",
  "id_token": "eyJ...",
  "refresh_token": "..."
}
```

### Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /jwks` | Public signing keys |
| `GET`/`POST /userinfo` | Claims for an access token. Also fails once the grant is removed |
| `POST /revoke` | Revoke a refresh token (RFC 7009). Needs client auth |
| `GET /logout` | Sign out. Needs `id_token_hint` |
| `GET /consent?request=` | Describe the pending request (needs a Spurs session) |
| `POST /consent` | `{ request, approve }`. Returns `{ redirect }` |

All paths are under the issuer, for example `/api/oidc/token`. `/authorize`, `/token` and `/revoke` are limited to 60 requests per minute per IP.

---

## 3. Scopes and claims

| Scope | Claims added | Shown to the user as |
|---|---|---|
| `openid` | `sub` (required) | Confirm who you are |
| `profile` | `name`, `account_type` | Your name and account type |
| `email` | `email`, `email_verified` | Your email address and whether it is verified |
| `phone` | `phone_number` (when set) | Your phone number |
| `offline_access` | none, enables a refresh token | Stay connected when you are not using the app |

`sub` is the Spurs user id as a string. Scopes are a fixed list. Custom scopes need a code change in `config/oidc.ts` and `claims.ts`.

---

## 4. Tokens

| Token | Format | Lifetime (default) | Env |
|---|---|---|---|
| Authorization code | opaque, single use | 60 s | `OIDC_CODE_TTL` |
| Access token | JWT RS256, `typ: at+jwt` | 600 s | `OIDC_ACCESS_TTL` |
| ID token | JWT RS256 | 600 s | `OIDC_ID_TOKEN_TTL` |
| Refresh token | opaque, rotated | 30 days | `OIDC_REFRESH_TTL_DAYS` |
| Consent request | JWT HS256 | 600 s | `OIDC_REQUEST_TTL` |
| Service token (added) | JWT RS256, `typ: at+jwt` | 900 s | `OIDC_SERVICE_TTL` |

Access token claims: `iss`, `sub` (user id), `aud` (the client's `client_id`), `scope`, `client_id`, `gid` (grant id), `exp`, `jti`.

ID token claims: `iss`, `sub`, `aud` (client id), `exp`, `auth_time`, `nonce` (when sent), plus the scope claims above.

Only hashes of codes, refresh tokens and client secrets are stored (SHA-256).

### Verifying an access token (your API)

1. Fetch `/jwks`, cache it, refetch on an unknown `kid`.
2. Accept only `alg: RS256` and `typ: at+jwt`.
3. Check `iss`, `exp`, and that `aud` is one of your `client_id`s.
4. Require `gid` (number) and `client_id`. That marks it as a user token.

The SDK does all of this: `createVerifier` in `@spurs/auth/server`. With `strict: true` it also calls `/userinfo` so a removed app stops working immediately rather than at token expiry.

### Replay and reuse protection

- A code used twice fails and **deletes all refresh tokens of that grant**.
- A refresh token used twice (reuse) fails and **deletes all refresh tokens of that grant**. This detects theft but also hits clients that refresh concurrently. The SDK serialises refreshes to avoid this.

---

## 5. Registering a client

**(added)** `oidc:client:create`:

```bash
# first-party SPA (public, no consent)
npm run artisan -- oidc:client:create "VendPro" --first-party --public \
  --redirect=http://localhost:5174/callback \
  --logout-redirect=http://localhost:5174 \
  --scopes=openid,profile,email,phone,offline_access

# third-party server app (confidential, consent required)
npm run artisan -- oidc:client:create "Acme Billing" \
  --redirect=https://acme.example/callback \
  --scopes=openid,profile,email
```

The `client_secret` is printed once. Only its hash is stored.

Until that command exists, insert a row into `oauth_clients` manually (`secret_hash` = `sha256(secret)` hex, JSON arrays for `redirect_uris`, `post_logout_redirect_uris`, `allowed_scopes`).

### Client fields

| Column | Meaning |
|---|---|
| `client_id` | Public identifier |
| `secret_hash` | SHA-256 of the secret, `NULL` for public clients |
| `type` | `first_party` or `third_party` |
| `redirect_uris` | Exact-match allow list |
| `post_logout_redirect_uris` | Exact-match allow list for logout |
| `allowed_scopes` | Scopes this client may ever request |
| `is_active` | Set to `false` to disable instantly |

---

## 6. Third-party apps

Same flow as section 2, with these differences:

- The user sees a consent screen listing the permissions. Approval is stored in `oauth_grants`.
- Consent is asked again only when the app requests a scope not yet granted, or sends `prompt=consent`.
- No refresh token unless the app asks for `offline_access`.
- A user can remove an app at any time (`DELETE /api/auth/connected-apps/{id}`). That deletes the grant, its codes and its refresh tokens.
- Browser apps need their origin in `CORS_ORIGINS` in production.

---

## 7. Spurs to Spurs (service authentication) **(added)**

For one Spurs backend calling another, or calling Accounts. No user, no browser, no consent. It uses the OAuth **client credentials** grant with an internal secret per service.

```
 Spurs service                 Accounts                      Internal API
     | POST /token                |                               |
     |  grant_type=client_credentials, Basic(id:secret)           |
     |--------------------------->|                               |
     |<-- service JWT (15 min) ---|                               |
     | GET /api/internal/... Authorization: Bearer <service JWT>  |
     |----------------------------------------------------------->|
     |                            verify signature, aud, scope    |
```

### Rules

- Only `first_party` **and** confidential clients may use `client_credentials`.
- Service tokens carry **service scopes** only (`users:read`, `users:introspect`), configured in `oidc.serviceScopes`. They can never be requested through `/authorize`.
- Audience is `spurs-internal` (`OIDC_INTERNAL_AUDIENCE`). User-token code rejects it, and service middleware rejects user tokens.
- No refresh tokens. The service just requests a new token near expiry.

### Register a service

```bash
npm run artisan -- oidc:client:create "VendPro API" --service --scopes=users:read
```

Store `client_id` and `client_secret` in that service's environment only.

### Request a token

```bash
curl -X POST https://accounts.example.com/api/oidc/token \
  -u "$SPURS_SERVICE_ID:$SPURS_SERVICE_SECRET" \
  -d grant_type=client_credentials \
  -d scope=users:read
```

### SDK

```ts
import { createServiceClient } from '@spurs/auth/service';

const spurs = createServiceClient({
  issuer: process.env.SPURS_ISSUER!,
  clientId: process.env.SPURS_SERVICE_ID!,
  clientSecret: process.env.SPURS_SERVICE_SECRET!,
});

const res = await spurs.fetch(`${process.env.SPURS_API}/api/internal/users/42`);
```

It caches the token, shares one in-flight request, and retries once on `401`.

### Protecting an internal route

```ts
Route.get('/users/{id}', [internalUserController, 'show'])
  .middleware('service:users:read');
```

`service:<scope>` is a middleware alias backed by `serviceAuth()`. It sets `req.service` (`clientId`, `scopes`).

### Operational rules

- One client per service, so each can be revoked or rotated alone.
- Never expose `/api/internal/*` to the public internet. Restrict it at the proxy or network.
- Rotate secrets on a schedule. Set `is_active = false` on a client to cut it off immediately (tokens still pass until they expire, 15 minutes by default).

---

## 8. Using the JS SDK (`@spurs/auth`)

| Entry point | For |
|---|---|
| `@spurs/auth` | Apps that sign users in (browser, or Node with the stateless methods) |
| `@spurs/auth/server` | APIs verifying user access tokens |
| `@spurs/auth/service` **(added)** | Backends calling other Spurs services |

```ts
import { SpursAuth } from '@spurs/auth';

export const auth = new SpursAuth({
  issuer: 'http://localhost:8080/api/oidc',
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: location.origin,
});

await auth.signIn({ returnTo: '/dashboard' });             // button
const { user, returnTo } = await auth.handleRedirectCallback(); // /callback page
await auth.fetch('/api/wallet');                            // Bearer + auto refresh
await auth.signOutEverywhere();                             // app and Spurs account
```

See `sdk/js/README.md` for the full API.

---

## 9. Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ISSUER` | `${APP_URL}/api/oidc` | Must match the `iss` clients see |
| `OIDC_PRIVATE_KEY` | none | RSA PEM, `\n` escapes allowed. **Required in production** |
| `OIDC_KEY_PATH` | `storage/oidc/private.pem` | Dev only, auto-generated when missing |
| `OIDC_ACCESS_TTL` | `600` | Seconds |
| `OIDC_ID_TOKEN_TTL` | `600` | Seconds |
| `OIDC_CODE_TTL` | `60` | Seconds |
| `OIDC_REQUEST_TTL` | `600` | Seconds |
| `OIDC_REFRESH_TTL_DAYS` | `30` | Days |
| `OIDC_SERVICE_TTL` | `900` | Seconds **(added)** |
| `OIDC_INTERNAL_AUDIENCE` | `spurs-internal` | **(added)** |
| `JWT_SECRET` | dev default | Signs consent request tokens. **Required in production** |
| `FRONTEND_URL` | `http://localhost:5173` | Login, consent and error pages |
| `CORS_ORIGINS` | `http://localhost:3000` | Needed for third-party browser apps in production |

### Database tables

`oauth_clients`, `oauth_grants` (unique per user and client), `oauth_codes`, `oauth_refresh_tokens`. Run `npm run artisan -- migrate`.

---

## 10. Error codes

Token endpoint errors use the OAuth shape `{ "error": "...", "error_description": "..." }`.

| Code | Meaning |
|---|---|
| `invalid_request` | Missing or malformed parameter |
| `invalid_client` | Unknown client or wrong secret (HTTP 401) |
| `invalid_grant` | Bad, used, or expired code or refresh token, PKCE failure, redirect mismatch |
| `unsupported_grant_type` | Use `authorization_code`, `refresh_token` or `client_credentials` |
| `unauthorized_client` | Client disabled or not allowed to use this grant |
| `invalid_scope` | Scope unknown or not allowed for the client |
| `login_required` | `prompt=none` and no session |
| `consent_required` | `prompt=none` and consent missing |
| `access_denied` | User denied consent |
| `invalid_token` | `/userinfo` token invalid or app removed (HTTP 401) |

---

## 11. Security model

- **PKCE (S256) is mandatory** for every client, including confidential ones.
- **Exact redirect matching.** No wildcards or partial matches.
- **Signed consent request.** The frontend cannot alter the pending authorization.
- **`iss` returned in every authorization response** (RFC 9207) against mix-up attacks. The SDK checks it.
- **Algorithm pinned to RS256**. `none` and HS256 tokens are rejected.
- **Hashes only** stored for codes, refresh tokens and secrets. Secrets are shown once.
- **Rotation and replay detection** on refresh tokens and codes.
- **Separate audiences**: user tokens use the client id, service tokens use `spurs-internal`.

---

## 12. Known limitations

| Limitation | Effect | Mitigation |
|---|---|---|
| Access tokens are stateless JWTs | A removed app's token works until it expires (up to 10 min) | Shorter `OIDC_ACCESS_TTL`, `strict: true` in the SDK, or an introspection endpoint |
| No token introspection endpoint | APIs cannot ask "is this token still valid" except via `/userinfo` | Add RFC 7662 `/introspect` |
| Single signing key, no rotation | Changing the key invalidates all tokens | Publish retired public keys in JWKS while rotating |
| `aud` equals the client id | A resource API must list every client id it accepts | Dedicated API audiences if the list grows |
| `/authorize` reads the session cookie only | Frontend and API must share a site in production | Set a shared cookie domain |
| Logout is per app | Other apps' sessions stay alive | Back-channel logout |
| `prompt` supports `none` and `consent` | No forced re-login, no `max_age`, no `login_hint` | Planned |
| No dynamic client registration | Clients are created by an operator | By design |
| Fixed scope list | No custom scopes or claims | Edit config and `claims.ts` |

---

## 13. Production checklist

- [ ] `OIDC_PRIVATE_KEY` set (RSA 2048+), backed up, **not** in git
- [ ] `JWT_SECRET` set to a long random value (`npm run artisan -- key:generate --write`)
- [ ] `OIDC_ISSUER` is the public HTTPS URL and identical in every client
- [ ] `FRONTEND_URL` and `CORS_ORIGINS` set
- [ ] Cookie `secure` on, frontend and API on the same site
- [ ] Redirect URIs are HTTPS and exact
- [ ] Service secrets live only in server environments
- [ ] `/api/internal/*` blocked from the public internet
- [ ] Migrations run, expired codes and refresh tokens cleaned (done on issue today)
- [ ] A plan for key rotation exists before the first rotation is needed