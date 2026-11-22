import { normalizeIssuer } from './util.js';
/** Production Spurs OIDC issuer. */
export const DEFAULT_ISSUER = 'https://accounts.spurs.com.ng/api/oidc';
/** Cookie set by the Accounts backend after sign-in. */
export const AUTH_COOKIE_NAME = 'auth_token';
export function readEnv() {
    const proc = globalThis.process;
    return proc?.env ?? {};
}
export function resolveIssuer(explicit, env = readEnv()) {
    return normalizeIssuer(explicit || env.SPURS_ISSUER || DEFAULT_ISSUER);
}
/** Convert a full OIDC issuer into the Accounts public origin. */
export function accountsOrigin(issuer) {
    return normalizeIssuer(issuer).replace(/\/api\/oidc$/, '');
}
//# sourceMappingURL=constants.js.map