/**
 * An OAuth error from the server or an SDK-specific failure.
 */
export class SpursAuthError extends Error {
    code;
    status;
    constructor(code, message, status, options) {
        super(message, options);
        this.code = code;
        this.status = status;
        this.name = 'SpursAuthError';
    }
}
//# sourceMappingURL=errors.js.map