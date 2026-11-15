import type { JwtClaims } from './types.js';
export interface JwtHeader {
    alg: string;
    kid?: string;
    typ?: string;
}
export interface DecodedJwt<T extends JwtClaims = JwtClaims> {
    header: JwtHeader;
    payload: T;
    signingInput: string;
    signature: Uint8Array;
}
export declare function decodeJwt<T extends JwtClaims = JwtClaims>(token: string): DecodedJwt<T>;
export declare class JwksCache {
    private readonly getUri;
    private readonly fetchFn;
    private readonly ttlMs;
    private keys;
    private loadedAt;
    private loading;
    constructor(getUri: () => Promise<string>, fetchFn: typeof fetch, ttlMs?: number);
    get(kid: string | undefined): Promise<CryptoKey>;
    private find;
    private load;
    private fetchKeys;
}
export interface VerifyOptions {
    issuer: string;
    audience?: string | string[];
    leewaySeconds?: number;
    typ?: string;
}
export declare function verifyJwt<T extends JwtClaims = JwtClaims>(token: string, jwks: JwksCache, options: VerifyOptions): Promise<DecodedJwt<T>>;
//# sourceMappingURL=jwt.d.ts.map