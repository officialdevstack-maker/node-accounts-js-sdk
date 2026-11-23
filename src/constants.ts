import { normalizeIssuer } from './util.js';

/** Production Spurs OIDC issuer. */
export const DEFAULT_ISSUER = 'https://node-accounts-backend.onrender.com/api/oidc';

/** Cookie set by the Accounts backend after sign-in. */
export const AUTH_COOKIE_NAME = 'auth_token';

export function readEnv(): Record<string, string | undefined> {
  const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return proc?.env ?? {};
}

export function resolveIssuer(explicit?: string, env = readEnv()): string {
  return normalizeIssuer(explicit || env.SPURS_ISSUER || DEFAULT_ISSUER);
}

/** Convert a full OIDC issuer into the Accounts public origin. */
export function accountsOrigin(issuer: string): string {
  return normalizeIssuer(issuer).replace(/\/api\/oidc$/, '');
}
