import type { SpursUser } from './types.js';
export declare function isPublicPath(pathname: string, pattern: string): boolean;
export interface SpursNextOptions {
    clientId?: string;
    clientSecret?: string;
    sessionSecret?: string;
    appUrl?: string;
    issuer?: string;
    scope?: string;
    basePath?: string;
    sessionSeconds?: number;
    publicPaths?: string[];
    apiPaths?: string[];
    logoutRedirect?: string;
}
export declare function createSpursNext(options?: SpursNextOptions): {
    proxy: (request: {
        nextUrl: {
            pathname: string;
            search?: string;
        };
        cookies: {
            get(name: string): {
                value: string;
            } | undefined;
        };
    }) => Promise<unknown>;
    GET: (request: Request) => Promise<Response>;
    getUser: () => Promise<SpursUser | null>;
    requireUser: (returnTo?: string) => Promise<SpursUser>;
    signInUrl: (returnTo?: string) => string;
    signOutUrl: (options?: {
        everywhere?: boolean;
    }) => string;
};
export declare function createSpursProxy(options?: SpursNextOptions): (request: {
    nextUrl: {
        pathname: string;
        search?: string;
    };
    cookies: {
        get(name: string): {
            value: string;
        } | undefined;
    };
}) => Promise<unknown>;
export declare function createSpursAuthRoute(options?: SpursNextOptions): (request: Request) => Promise<Response>;
//# sourceMappingURL=next.d.ts.map