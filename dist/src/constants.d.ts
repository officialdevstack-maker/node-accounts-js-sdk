/** Production Spurs OIDC issuer. */
export declare const DEFAULT_ISSUER = "https://accounts.spurs.com.ng/api/oidc";
/** Cookie set by the Accounts backend after sign-in. */
export declare const AUTH_COOKIE_NAME = "auth_token";
export declare function readEnv(): Record<string, string | undefined>;
export declare function resolveIssuer(explicit?: string, env?: Record<string, string | undefined>): string;
/** Convert a full OIDC issuer into the Accounts public origin. */
export declare function accountsOrigin(issuer: string): string;
//# sourceMappingURL=constants.d.ts.map