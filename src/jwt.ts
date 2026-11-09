import { SpursAuthError } from './errors.js';
import type { JwtClaims } from './types.js';
import { base64urlDecode, nowSeconds, normalizeIssuer } from './util.js';

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

const invalid = (message: string) => new SpursAuthError('invalid_token', message);

export function decodeJwt<T extends JwtClaims = JwtClaims>(token: string): DecodedJwt<T> {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part === '')) throw invalid('Malformed token.');

  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const header = JSON.parse(decoder.decode(base64urlDecode(parts[0]!))) as unknown;
    const payload = JSON.parse(decoder.decode(base64urlDecode(parts[1]!))) as unknown;
    if (
      header === null || typeof header !== 'object' ||
      payload === null || typeof payload !== 'object' || Array.isArray(payload)
    ) {
      throw new Error('JWT header or payload is not an object.');
    }

    return {
      header: header as JwtHeader,
      payload: payload as T,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64urlDecode(parts[2]!),
    };
  } catch (cause) {
    if (cause instanceof SpursAuthError) throw cause;
    throw new SpursAuthError('invalid_token', 'Malformed token.', undefined, { cause });
  }
}

type Jwk = JsonWebKey & { kid?: string };

export class JwksCache {
  private keys = new Map<string, CryptoKey>();
  private loadedAt = 0;
  private loading: Promise<void> | undefined;

  constructor(
    private readonly getUri: () => Promise<string>,
    private readonly fetchFn: typeof fetch,
    private readonly ttlMs = 10 * 60_000,
  ) {}

  async get(kid: string | undefined): Promise<CryptoKey> {
    const age = Date.now() - this.loadedAt;
    const stale = age > this.ttlMs;
    if (!stale) {
      const hit = this.find(kid);
      if (hit) return hit;
    }

    if (stale || age > 30_000) await this.load();

    const key = this.find(kid);
    if (!key) throw invalid('The token was signed with an unknown key.');
    return key;
  }

  private find(kid: string | undefined): CryptoKey | undefined {
    if (kid) return this.keys.get(kid);
    return this.keys.size === 1 ? this.keys.values().next().value : undefined;
  }

  private load(): Promise<void> {
    if (this.loading) return this.loading;
    const run = this.fetchKeys().finally(() => {
      this.loading = undefined;
    });
    this.loading = run;
    return run;
  }

  private async fetchKeys(): Promise<void> {
    let response: Response;
    try {
      response = await this.fetchFn(await this.getUri(), { headers: { Accept: 'application/json' } });
    } catch (cause) {
      throw new SpursAuthError('jwks_unavailable', 'Could not download the signing keys.', undefined, { cause });
    }
    if (!response.ok) {
      throw new SpursAuthError('jwks_unavailable', `Signing keys request failed (${response.status}).`, response.status);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      throw new SpursAuthError('jwks_unavailable', 'Signing keys returned invalid JSON.', undefined, { cause });
    }
    if (body === null || typeof body !== 'object' || !Array.isArray((body as { keys?: unknown }).keys)) {
      throw new SpursAuthError('jwks_unavailable', 'Signing keys returned an invalid document.');
    }

    const next = new Map<string, CryptoKey>();
    for (const candidate of (body as { keys: unknown[] }).keys) {
      if (candidate === null || typeof candidate !== 'object') continue;
      const jwk = candidate as Jwk;
      if (
        jwk.kty !== 'RSA' ||
        typeof jwk.kid !== 'string' ||
        !jwk.kid ||
        (jwk.use && jwk.use !== 'sig') ||
        (jwk.alg && jwk.alg !== 'RS256')
      ) {
        continue;
      }
      try {
        const key = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['verify'],
        );
        next.set(jwk.kid, key);
      } catch {
        continue;
      }
    }
    if (!next.size) throw new SpursAuthError('jwks_unavailable', 'No supported RS256 signing keys were found.');
    this.keys = next;
    this.loadedAt = Date.now();
  }
}

export interface VerifyOptions {
  issuer: string;
  audience?: string | string[];
  leewaySeconds?: number;
  typ?: string;
}

const cleanTyp = (typ: string | undefined) => typ?.replace(/^application\//i, '').toLowerCase();

export async function verifyJwt<T extends JwtClaims = JwtClaims>(
  token: string,
  jwks: JwksCache,
  options: VerifyOptions,
): Promise<DecodedJwt<T>> {
  const jwt = decodeJwt<T>(token);
  if (jwt.header.alg !== 'RS256') throw invalid('Unsupported signing algorithm.');
  if (options.typ && cleanTyp(jwt.header.typ) !== options.typ) throw invalid('Wrong token type.');

  const key = await jwks.get(jwt.header.kid);
  let valid: boolean;
  try {
    const signature = new Uint8Array(jwt.signature.length);
    signature.set(jwt.signature);
    valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      signature,
      new TextEncoder().encode(jwt.signingInput),
    );
  } catch (cause) {
    throw new SpursAuthError('invalid_token', 'Invalid token signature.', undefined, { cause });
  }
  if (!valid) throw invalid('Invalid token signature.');

  const claims = jwt.payload;
  const now = nowSeconds();
  const leeway = options.leewaySeconds ?? 60;
  if (!Number.isFinite(leeway) || leeway < 0) {
    throw new SpursAuthError('invalid_config', '`leewaySeconds` must be a non-negative number.');
  }
  if (typeof claims.iss !== 'string' || normalizeIssuer(claims.iss) !== normalizeIssuer(options.issuer)) {
    throw invalid('Token issuer mismatch.');
  }
  if (options.audience !== undefined) {
    const wanted = [options.audience].flat();
    const got = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!got.some((aud) => typeof aud === 'string' && wanted.includes(aud))) {
      throw invalid('Token audience mismatch.');
    }
  }
  if (typeof claims.sub !== 'string' || claims.sub === '') throw invalid('Token has no subject.');
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp + leeway < now) {
    throw invalid('Token has expired.');
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - leeway > now)) {
    throw invalid('Token is not valid yet.');
  }
  return jwt;
}
