import { AUTH_COOKIE_NAME, accountsOrigin, resolveIssuer } from './constants.js';
import { SpursAuthError } from './errors.js';
import type { SpursSessionOptions, SpursUser } from './types.js';
import { record, text } from './util.js';

const MAX_CACHE = 1000;
const MISS_TTL_MS = 5_000;

export function readCookie(header: string | null | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0 || part.slice(0, idx).trim() !== name) continue;
    const raw = part.slice(idx + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  return undefined;
}

function toUser(data: Record<string, unknown>, origin: string): SpursUser | null {
  const id = Number(data.id);
  if (!Number.isSafeInteger(id) || id < 1) return null;

  const user: SpursUser = { sub: String(id), id };
  const name = text(data.fullname) ?? text(data.name);
  const email = text(data.email);
  const phone = text(data.phone);
  const accountType = text(data.accountType);
  const avatar = text(data.avatarUrl);

  if (name) user.name = name;
  if (email) user.email = email;
  if (phone) user.phone_number = phone;
  if (typeof data.isVerified === 'boolean') user.email_verified = data.isVerified;
  if (accountType === 'user' || accountType === 'business' || accountType === 'developer') {
    user.account_type = accountType;
  }
  if (avatar) user.picture = /^https?:\/\//i.test(avatar) ? avatar : `${origin}${avatar}`;
  return user;
}

export class SpursSession {
  readonly issuer: string;
  readonly origin: string;
  readonly cookieName: string;
  private readonly loginPath: string;
  private readonly ttlMs: number;
  private readonly fetchFn: typeof fetch;
  private readonly cache = new Map<string, { user: SpursUser | null; expiresAt: number }>();
  private readonly pending = new Map<string, Promise<SpursUser | null>>();

  constructor(options: SpursSessionOptions = {}) {
    this.issuer = resolveIssuer(options.issuer);
    this.origin = accountsOrigin(this.issuer);
    this.cookieName = options.cookieName ?? AUTH_COOKIE_NAME;
    this.loginPath = options.loginPath ?? '/sso/continue';
    this.ttlMs = (options.cacheSeconds ?? 30) * 1000;

    const fetchFn = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!fetchFn) throw new SpursAuthError('invalid_config', 'No fetch available. Pass `fetch` in the options.');
    this.fetchFn = fetchFn;
  }

  verify(token: string | undefined | null): Promise<SpursUser | null> {
    if (!token) return Promise.resolve(null);

    const hit = this.cache.get(token);
    if (hit && hit.expiresAt > Date.now()) return Promise.resolve(hit.user);

    let run = this.pending.get(token);
    if (!run) {
      run = this.lookup(token).finally(() => this.pending.delete(token));
      this.pending.set(token, run);
    }
    return run;
  }

  userFromCookieHeader(header: string | null | undefined): Promise<SpursUser | null> {
    return this.verify(readCookie(header, this.cookieName));
  }

  userFromRequest(request: { headers: { get(name: string): string | null } }): Promise<SpursUser | null> {
    return this.userFromCookieHeader(request.headers.get('cookie'));
  }

  invalidate(token: string): void {
    this.cache.delete(token);
  }

  loginUrl(returnTo: string): string {
    return `${this.origin}${this.loginPath}?return_to=${encodeURIComponent(returnTo)}`;
  }

  logoutUrl(returnTo?: string): string {
    const base = `${this.origin}/logout`;
    return returnTo ? `${base}?return_to=${encodeURIComponent(returnTo)}` : base;
  }

  accountUrl(): string {
    return `${this.origin}/me`;
  }

  private remember(token: string, user: SpursUser | null, ttlMs: number): void {
    if (this.cache.size >= MAX_CACHE) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(token, { user, expiresAt: Date.now() + ttlMs });
  }

  private async lookup(token: string): Promise<SpursUser | null> {
    let response: Response;
    try {
      response = await this.fetchFn(`${this.origin}/api/auth/profile`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        cache: 'no-store',
      });
    } catch (cause) {
      throw new SpursAuthError('network_error', 'Could not reach Spurs Accounts.', undefined, { cause });
    }

    if (response.status === 401 || response.status === 403) {
      this.remember(token, null, MISS_TTL_MS);
      return null;
    }
    if (!response.ok) {
      throw new SpursAuthError('server_error', `Spurs Accounts returned ${response.status}.`, response.status);
    }

    let body: Record<string, unknown> | null;
    try {
      body = record(await response.json());
    } catch (cause) {
      throw new SpursAuthError('invalid_response', 'Spurs Accounts returned invalid JSON.', response.status, { cause });
    }

    const user = toUser(record(body?.data) ?? body ?? {}, this.origin);
    if (!user) throw new SpursAuthError('invalid_response', 'The profile response has no user.', response.status);

    this.remember(token, user, this.ttlMs);
    return user;
  }
}

export function createSpursSession(options: SpursSessionOptions = {}): SpursSession {
  return new SpursSession(options);
}
