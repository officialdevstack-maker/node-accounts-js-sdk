import type { SpursSessionOptions, SpursUser } from './types.js';
export declare function readCookie(header: string | null | undefined, name: string): string | undefined;
export declare class SpursSession {
    readonly issuer: string;
    readonly origin: string;
    readonly cookieName: string;
    private readonly loginPath;
    private readonly ttlMs;
    private readonly fetchFn;
    private readonly cache;
    private readonly pending;
    constructor(options?: SpursSessionOptions);
    verify(token: string | undefined | null): Promise<SpursUser | null>;
    userFromCookieHeader(header: string | null | undefined): Promise<SpursUser | null>;
    userFromRequest(request: {
        headers: {
            get(name: string): string | null;
        };
    }): Promise<SpursUser | null>;
    invalidate(token: string): void;
    loginUrl(returnTo: string): string;
    logoutUrl(returnTo?: string): string;
    accountUrl(): string;
    private remember;
    private lookup;
}
export declare function createSpursSession(options?: SpursSessionOptions): SpursSession;
//# sourceMappingURL=session.d.ts.map