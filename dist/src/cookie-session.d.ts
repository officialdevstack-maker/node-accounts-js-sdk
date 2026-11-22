export declare function readCookie(header: string | null | undefined, name: string): string | undefined;
export declare function sealCookie(payload: object, secret: string, ttlSeconds: number): Promise<string>;
export declare function openCookie<T extends object>(value: string | undefined, secret: string): Promise<T | null>;
export declare function serializeCookie(name: string, value: string, options: {
    maxAge: number;
    secure: boolean;
}): string;
//# sourceMappingURL=cookie-session.d.ts.map