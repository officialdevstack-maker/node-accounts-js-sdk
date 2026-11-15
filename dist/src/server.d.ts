import type { AccessTokenClaims } from './types.js';
export interface VerifierOptions {
    issuer: string;
    audience: string | string[];
    /** Query RFC 7662 introspection to reject disconnected apps before the access token expires. */
    strict?: boolean;
    /** Confidential resource-server credentials authorized to introspect tokens. */
    introspectionClient?: {
        clientId: string;
        clientSecret: string;
    };
    leewaySeconds?: number;
    fetch?: typeof fetch;
}
export interface VerifiedToken {
    sub: string;
    principalType: 'user' | 'client';
    clientId: string;
    grantId: number;
    scopes: string[];
    claims: AccessTokenClaims;
}
export interface RequestLike {
    headers: Record<string, string | string[] | undefined>;
    spurs?: VerifiedToken | undefined;
}
export interface ResponseLike {
    status(code: number): ResponseLike;
    setHeader(name: string, value: string): unknown;
    json(body: unknown): unknown;
}
export type NextLike = (error?: unknown) => void;
export declare function getBearerToken(headers: RequestLike['headers']): string | null;
export declare function createVerifier(options: VerifierOptions): {
    verify: (token: string) => Promise<VerifiedToken>;
    middleware: (guard?: {
        scopes?: string[];
    }) => (req: RequestLike, res: ResponseLike, next: NextLike) => Promise<void>;
};
//# sourceMappingURL=server.d.ts.map