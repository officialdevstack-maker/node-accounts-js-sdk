import { SpursSession } from './session.js';
import type { SpursUser } from './types.js';
export declare function spurs(): SpursSession;
export declare function isPublicPath(pathname: string, pattern: string): boolean;
export declare function getSpursUser(session?: SpursSession): Promise<SpursUser | null>;
export declare function requireSpursUser(returnTo?: string, session?: SpursSession): Promise<SpursUser>;
export interface SpursProxyOptions {
    publicPaths?: string[];
    apiPaths?: string[];
    session?: SpursSession;
    appUrl?: string;
}
export declare function createSpursProxy(options?: SpursProxyOptions): (request: {
    nextUrl: {
        pathname: string;
        search?: string;
    };
    url: string;
    cookies: {
        get(name: string): {
            value: string;
        } | undefined;
    };
}) => Promise<unknown>;
//# sourceMappingURL=next.d.ts.map