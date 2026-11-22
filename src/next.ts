import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { SpursAuth } from './client.js';
import { readEnv, resolveIssuer } from './constants.js';
import { openCookie, readCookie, sealCookie, serializeCookie } from './cookie-session.js';
import { SpursAuthError } from './errors.js';
import type { IdTokenClaims, SpursUser } from './types.js';

const SESSION_COOKIE = 'spurs_app';
const FLOW_COOKIE = 'spurs_oidc';
const FLOW_SECONDS = 600;

interface FlowPayload { s: string; n: string; v: string; r: string }
interface SessionPayload { u: SpursUser; idt?: string }

export function isPublicPath(pathname: string, pattern: string): boolean {
  if (pattern === '/') return pathname === '/';
  const base = pattern.replace(/\/+$/, '');
  return pathname === base || pathname.startsWith(`${base}/`);
}

function safeReturnTo(value: string | null, appUrl: string): string {
  if (!value) return '/';
  try {
    const target = new URL(value, appUrl);
    if (target.origin !== new URL(appUrl).origin) return '/';
    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return '/';
  }
}

function toUser(claims: IdTokenClaims): SpursUser {
  const user: SpursUser = { sub: claims.sub };
  for (const key of ['name', 'account_type', 'email', 'email_verified', 'phone_number'] as const) {
    if (claims[key] !== undefined) (user as Record<string, unknown>)[key] = claims[key];
  }
  return user;
}

function respond(status: number, headers: Record<string, string>, setCookies: string[], body: string | null = null) {
  const out = new Headers({ 'Cache-Control': 'no-store', ...headers });
  for (const cookie of setCookies) out.append('Set-Cookie', cookie);
  return new Response(body, { status, headers: out });
}

const redirectTo = (location: string, setCookies: string[] = []) => respond(302, { Location: location }, setCookies);
const message = (status: number, text: string, setCookies: string[] = []) =>
  respond(status, { 'Content-Type': 'text/plain; charset=utf-8' }, setCookies, text);

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

export function createSpursNext(options: SpursNextOptions = {}) {
  const basePath = `/${(options.basePath ?? '/auth').replace(/^\/+|\/+$/g, '')}`;
  const publicPaths = [...(options.publicPaths ?? []), basePath];
  const apiPaths = options.apiPaths ?? ['/api/'];
  const sessionSeconds = options.sessionSeconds ?? 8 * 3600;
  const logoutRedirect = options.logoutRedirect ?? '/';

  interface Resolved {
    auth: SpursAuth;
    appUrl: string;
    secret: string;
    secure: boolean;
  }
  let cached: Resolved | undefined;

  function resolve(): Resolved {
    if (cached) return cached;
    const env = readEnv();
    const clientId = options.clientId ?? env.SPURS_CLIENT_ID;
    const clientSecret = options.clientSecret ?? env.SPURS_CLIENT_SECRET;
    const secret = options.sessionSecret ?? env.SPURS_SESSION_SECRET;
    const vercelHost = env.VERCEL_PROJECT_PRODUCTION_URL;
    const appUrl = (options.appUrl ?? env.APP_URL ?? (vercelHost ? `https://${vercelHost}` : undefined))?.replace(/\/+$/, '');

    if (!clientId) throw new Error('[spurs] clientId is required (SPURS_CLIENT_ID).');
    if (!secret) throw new Error('[spurs] sessionSecret is required (SPURS_SESSION_SECRET).');
    if (!appUrl) throw new Error('[spurs] appUrl is required (APP_URL).');

    cached = {
      appUrl,
      secret,
      secure: appUrl.startsWith('https://'),
      auth: new SpursAuth({
        issuer: resolveIssuer(options.issuer),
        clientId,
        ...(clientSecret ? { clientSecret } : {}),
        ...(options.scope ? { scope: options.scope } : {}),
        redirectUri: `${appUrl}${basePath}/callback`,
        storage: 'memory',
      }),
    };
    return cached;
  }

  async function readUser(token: string | undefined): Promise<SpursUser | null> {
    return (await openCookie<SessionPayload>(token, resolve().secret))?.u ?? null;
  }

  const loginPath = (returnTo: string) => `${basePath}/login?return_to=${encodeURIComponent(returnTo)}`;

  async function login(app: Resolved, url: URL): Promise<Response> {
    const returnTo = safeReturnTo(url.searchParams.get('return_to'), app.appUrl);
    const authRequest = await app.auth.createAuthorizationRequest(
      url.searchParams.get('prompt') === 'login' ? { prompt: 'login' } : {},
    );
    const flow = await sealCookie(
      { s: authRequest.state, n: authRequest.nonce, v: authRequest.codeVerifier, r: returnTo } satisfies FlowPayload,
      app.secret,
      FLOW_SECONDS,
    );
    return redirectTo(authRequest.url, [serializeCookie(FLOW_COOKIE, flow, { maxAge: FLOW_SECONDS, secure: app.secure })]);
  }

  async function callback(app: Resolved, request: Request, url: URL): Promise<Response> {
    const clearFlow = serializeCookie(FLOW_COOKIE, '', { maxAge: 0, secure: app.secure });
    const flow = await openCookie<FlowPayload>(readCookie(request.headers.get('cookie'), FLOW_COOKIE), app.secret);
    if (!flow) return message(400, 'Your sign-in session expired. Please go back and try again.', [clearFlow]);

    try {
      const tokens = await app.auth.exchangeCode(url.searchParams, {
        state: flow.s,
        nonce: flow.n,
        codeVerifier: flow.v,
      });
      if (!tokens.claims) throw new SpursAuthError('invalid_response', 'The server returned no ID token.');

      const session = await sealCookie(
        { u: toUser(tokens.claims), ...(tokens.idToken ? { idt: tokens.idToken } : {}) } satisfies SessionPayload,
        app.secret,
        sessionSeconds,
      );
      return redirectTo(`${app.appUrl}${flow.r}`, [
        clearFlow,
        serializeCookie(SESSION_COOKIE, session, { maxAge: sessionSeconds, secure: app.secure }),
      ]);
    } catch (error) {
      return message(401, error instanceof SpursAuthError ? error.message : 'Sign-in failed.', [clearFlow]);
    }
  }

  async function logout(app: Resolved, request: Request, url: URL): Promise<Response> {
    const clearSession = serializeCookie(SESSION_COOKIE, '', { maxAge: 0, secure: app.secure });
    const landing = `${app.appUrl}${logoutRedirect}`;

    if (url.searchParams.get('everywhere') === '1') {
      const session = await openCookie<SessionPayload>(readCookie(request.headers.get('cookie'), SESSION_COOKIE), app.secret);
      if (session?.idt) {
        const target = await app.auth.endSessionUrl({ idTokenHint: session.idt, postLogoutRedirectUri: landing });
        return redirectTo(target, [clearSession]);
      }
    }
    return redirectTo(landing, [clearSession]);
  }

  async function GET(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const action = url.pathname.slice(basePath.length).split('/').filter(Boolean)[0];
    const app = resolve();

    switch (action) {
      case 'login': return login(app, url);
      case 'callback': return callback(app, request, url);
      case 'logout': return logout(app, request, url);
      default: return message(404, 'Not found.');
    }
  }

  async function proxy(request: {
    nextUrl: { pathname: string; search?: string };
    cookies: { get(name: string): { value: string } | undefined };
  }) {
    const { NextResponse } = await import('next/server');
    const { pathname } = request.nextUrl;

    if (publicPaths.some((p) => isPublicPath(pathname, p))) return NextResponse.next();
    if (await readUser(request.cookies.get(SESSION_COOKIE)?.value)) return NextResponse.next();

    if (apiPaths.some((p) => isPublicPath(pathname, p))) {
      return NextResponse.json({ message: 'Unauthenticated.' }, { status: 401 });
    }

    const returnTo = `${pathname}${request.nextUrl.search ?? ''}`;
    return NextResponse.redirect(`${resolve().appUrl}${loginPath(returnTo)}`);
  }

  async function getUser(): Promise<SpursUser | null> {
    const store = await cookies();
    return readUser(store.get(SESSION_COOKIE)?.value);
  }

  async function requireUser(returnTo = '/'): Promise<SpursUser> {
    const user = await getUser();
    if (!user) redirect(loginPath(returnTo));
    return user;
  }

  return {
    proxy,
    GET,
    getUser,
    requireUser,
    signInUrl: (returnTo = '/') => loginPath(returnTo),
    signOutUrl: (options: { everywhere?: boolean } = {}) =>
      `${basePath}/logout${options.everywhere ? '?everywhere=1' : ''}`,
  };
}
