import { SpursAuthError } from './errors.js';
import { nowSeconds, normalizeIssuer, record, text } from './util.js';

export interface ServiceClientOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  fetch?: typeof fetch;
}

export function createServiceClient(options: ServiceClientOptions) {
  if (!options.issuer) throw new SpursAuthError('invalid_config', '`issuer` is required.');
  if (!options.clientId) throw new SpursAuthError('invalid_config', '`clientId` is required.');
  if (!options.clientSecret) throw new SpursAuthError('invalid_config', '`clientSecret` is required.');

  const issuer = normalizeIssuer(options.issuer);
  const fetchFn = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetchFn) throw new SpursAuthError('invalid_config', 'No fetch available. Pass `fetch` in the options.');

  let cached: { token: string; expiresAt: number } | undefined;
  let pending: Promise<string> | undefined;

  async function requestToken(): Promise<string> {
    const body = new URLSearchParams({ grant_type: 'client_credentials' });
    if (options.scope) body.set('scope', options.scope);

    let response: Response;
    try {
      const basic = btoa(`${encodeURIComponent(options.clientId)}:${encodeURIComponent(options.clientSecret)}`);
      response = await fetchFn(`${issuer}/token`, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${basic}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body,
      });
    } catch (cause) {
      throw new SpursAuthError('network_error', 'Could not reach the Spurs server.', undefined, { cause });
    }

    let data: Record<string, unknown> = {};
    try {
      const parsed = record(await response.json());
      if (parsed) data = parsed;
    } catch (cause) {
      if (response.ok) {
        throw new SpursAuthError('invalid_response', 'The Spurs server returned invalid JSON.', response.status, { cause });
      }
    }

    if (!response.ok) {
      throw new SpursAuthError(
        text(data.error) ?? 'server_error',
        text(data.error_description) ?? text(data.message) ?? `Token request failed (${response.status}).`,
        response.status,
      );
    }

    const token = text(data.access_token);
    if (!token) throw new SpursAuthError('invalid_response', 'The token response has no access_token.', response.status);
    if (data.token_type !== undefined && data.token_type !== 'Bearer') {
      throw new SpursAuthError('invalid_response', 'The token response uses an unsupported token type.', response.status);
    }

    const expiresIn = Number(data.expires_in);
    if (!Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw new SpursAuthError('invalid_response', 'The token response has an invalid expires_in value.', response.status);
    }

    cached = { token, expiresAt: nowSeconds() + expiresIn };
    return token;
  }

  async function getToken(): Promise<string> {
    if (cached && cached.expiresAt - 30 > nowSeconds()) return cached.token;
    if (!pending) {
      pending = requestToken().finally(() => {
        pending = undefined;
      });
    }
    return pending;
  }

  return {
    getToken,
    async fetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
      const send = async (token: string) => {
        const headers = new Headers(init.headers);
        headers.set('Authorization', `Bearer ${token}`);
        return fetchFn(url, { ...init, headers });
      };

      const token = await getToken();
      const response = await send(token);
      if (response.status !== 401) return response;

      if (cached?.token === token) cached = undefined;
      return send(await getToken());
    },
  };
}
