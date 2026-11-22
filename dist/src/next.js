import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { SpursAuth } from './client.js';
import { readEnv, resolveIssuer } from './constants.js';
import { openCookie, readCookie, sealCookie, serializeCookie } from './cookie-session.js';
import { SpursAuthError } from './errors.js';
const SESSION_COOKIE = 'spurs_app';
const FLOW_COOKIE = 'spurs_oidc';
const FLOW_SECONDS = 600;
export function isPublicPath(pathname, pattern) {
    if (pattern === '/')
        return pathname === '/';
    const base = pattern.replace(/\/+$/, '');
    return pathname === base || pathname.startsWith(`${base}/`);
}
function safeReturnTo(value, appUrl) {
    if (!value)
        return '/';
    try {
        const target = new URL(value, appUrl);
        if (target.origin !== new URL(appUrl).origin)
            return '/';
        return `${target.pathname}${target.search}${target.hash}`;
    }
    catch {
        return '/';
    }
}
function toUser(claims) {
    const user = { sub: claims.sub };
    for (const key of ['name', 'account_type', 'email', 'email_verified', 'phone_number']) {
        if (claims[key] !== undefined)
            user[key] = claims[key];
    }
    return user;
}
function respond(status, headers, setCookies, body = null) {
    const out = new Headers({ 'Cache-Control': 'no-store', ...headers });
    for (const cookie of setCookies)
        out.append('Set-Cookie', cookie);
    return new Response(body, { status, headers: out });
}
const redirectTo = (location, setCookies = []) => respond(302, { Location: location }, setCookies);
const message = (status, text, setCookies = []) => respond(status, { 'Content-Type': 'text/plain; charset=utf-8' }, setCookies, text);
export function createSpursNext(options = {}) {
    const basePath = `/${(options.basePath ?? '/auth').replace(/^\/+|\/+$/g, '')}`;
    const publicPaths = [...(options.publicPaths ?? []), basePath];
    const apiPaths = options.apiPaths ?? ['/api/'];
    const sessionSeconds = options.sessionSeconds ?? 8 * 3600;
    const logoutRedirect = options.logoutRedirect ?? '/';
    let base;
    let full;
    function resolveBase() {
        if (base)
            return base;
        const env = readEnv();
        const secret = options.sessionSecret ?? env.SPURS_SESSION_SECRET;
        const vercelHost = env.VERCEL_PROJECT_PRODUCTION_URL;
        const appUrl = (options.appUrl ?? env.APP_URL ?? (vercelHost ? `https://${vercelHost}` : undefined))?.replace(/\/+$/, '');
        if (!secret)
            throw new Error('[spurs] sessionSecret is required (SPURS_SESSION_SECRET).');
        if (!appUrl)
            throw new Error('[spurs] appUrl is required (APP_URL).');
        base = { appUrl, secret, secure: appUrl.startsWith('https://') };
        return base;
    }
    function resolve() {
        if (full)
            return full;
        const env = readEnv();
        const clientId = options.clientId ?? env.SPURS_CLIENT_ID;
        const clientSecret = options.clientSecret ?? env.SPURS_CLIENT_SECRET;
        if (!clientId)
            throw new Error('[spurs] clientId is required (SPURS_CLIENT_ID).');
        const b = resolveBase();
        full = {
            ...b,
            auth: new SpursAuth({
                issuer: resolveIssuer(options.issuer),
                clientId,
                ...(clientSecret ? { clientSecret } : {}),
                ...(options.scope ? { scope: options.scope } : {}),
                redirectUri: `${b.appUrl}${basePath}/callback`,
                storage: 'memory',
            }),
        };
        return full;
    }
    async function readUser(token) {
        return (await openCookie(token, resolveBase().secret))?.u ?? null;
    }
    const loginPath = (returnTo) => `${basePath}/login?return_to=${encodeURIComponent(returnTo)}`;
    async function login(app, url) {
        const returnTo = safeReturnTo(url.searchParams.get('return_to'), app.appUrl);
        const authRequest = await app.auth.createAuthorizationRequest(url.searchParams.get('prompt') === 'login' ? { prompt: 'login' } : {});
        const flow = await sealCookie({ s: authRequest.state, n: authRequest.nonce, v: authRequest.codeVerifier, r: returnTo }, app.secret, FLOW_SECONDS);
        return redirectTo(authRequest.url, [serializeCookie(FLOW_COOKIE, flow, { maxAge: FLOW_SECONDS, secure: app.secure })]);
    }
    async function callback(app, request, url) {
        const clearFlow = serializeCookie(FLOW_COOKIE, '', { maxAge: 0, secure: app.secure });
        const flow = await openCookie(readCookie(request.headers.get('cookie'), FLOW_COOKIE), app.secret);
        if (!flow)
            return message(400, 'Your sign-in session expired. Please go back and try again.', [clearFlow]);
        try {
            const tokens = await app.auth.exchangeCode(url.searchParams, {
                state: flow.s,
                nonce: flow.n,
                codeVerifier: flow.v,
            });
            if (!tokens.claims)
                throw new SpursAuthError('invalid_response', 'The server returned no ID token.');
            const session = await sealCookie({ u: toUser(tokens.claims), ...(tokens.idToken ? { idt: tokens.idToken } : {}) }, app.secret, sessionSeconds);
            return redirectTo(`${app.appUrl}${flow.r}`, [
                clearFlow,
                serializeCookie(SESSION_COOKIE, session, { maxAge: sessionSeconds, secure: app.secure }),
            ]);
        }
        catch (error) {
            return message(401, error instanceof SpursAuthError ? error.message : 'Sign-in failed.', [clearFlow]);
        }
    }
    async function logout(app, request, url) {
        const clearSession = serializeCookie(SESSION_COOKIE, '', { maxAge: 0, secure: app.secure });
        const landing = `${app.appUrl}${logoutRedirect}`;
        if (url.searchParams.get('everywhere') === '1') {
            const session = await openCookie(readCookie(request.headers.get('cookie'), SESSION_COOKIE), app.secret);
            if (session?.idt) {
                const target = await app.auth.endSessionUrl({ idTokenHint: session.idt, postLogoutRedirectUri: landing });
                return redirectTo(target, [clearSession]);
            }
        }
        return redirectTo(landing, [clearSession]);
    }
    async function GET(request) {
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
    async function proxy(request) {
        const { NextResponse } = await import('next/server');
        const { pathname } = request.nextUrl;
        if (publicPaths.some((p) => isPublicPath(pathname, p)))
            return NextResponse.next();
        if (await readUser(request.cookies.get(SESSION_COOKIE)?.value))
            return NextResponse.next();
        if (apiPaths.some((p) => isPublicPath(pathname, p))) {
            return NextResponse.json({ message: 'Unauthenticated.' }, { status: 401 });
        }
        const returnTo = `${pathname}${request.nextUrl.search ?? ''}`;
        return NextResponse.redirect(`${resolveBase().appUrl}${loginPath(returnTo)}`);
    }
    async function getUser() {
        const store = await cookies();
        return readUser(store.get(SESSION_COOKIE)?.value);
    }
    async function requireUser(returnTo = '/') {
        const user = await getUser();
        if (!user)
            redirect(loginPath(returnTo));
        return user;
    }
    return {
        proxy,
        GET,
        getUser,
        requireUser,
        signInUrl: (returnTo = '/') => loginPath(returnTo),
        signOutUrl: (options = {}) => `${basePath}/logout${options.everywhere ? '?everywhere=1' : ''}`,
    };
}
export function createSpursProxy(options = {}) {
    return createSpursNext(options).proxy;
}
export function createSpursAuthRoute(options = {}) {
    return createSpursNext(options).GET;
}
//# sourceMappingURL=next.js.map