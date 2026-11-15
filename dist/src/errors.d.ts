/**
 * An OAuth error from the server or an SDK-specific failure.
 */
export declare class SpursAuthError extends Error {
    readonly code: string;
    readonly status?: number | undefined;
    constructor(code: string, message: string, status?: number | undefined, options?: ErrorOptions);
}
//# sourceMappingURL=errors.d.ts.map