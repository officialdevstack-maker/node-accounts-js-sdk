/**
 * An OAuth error from the server or an SDK-specific failure.
 */
export class SpursAuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status?: number,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'SpursAuthError';
  }
}
