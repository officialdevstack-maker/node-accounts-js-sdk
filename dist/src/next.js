import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { readEnv } from './constants.js';
import { SpursSession } from './session.js';
let cached;
export function spurs() {
    cached ??= new SpursSession();
    return cached;
}
function absoluteReturnTo(returnTo, appUrl) {
    if (/^https?:\/\//i.test(returnTo) || !appUrl)
        return returnTo;
    return `${appUrl.replace(/\/+$/, '')}${returnTo.startsWith('/') ? '' : '/'}${returnTo}`;
}
export function isPublicPath(pathname, pattern) {
    if (pattern === '/')
        return pathname === '/';
    const base = pattern.replace(/\/+$/, '');
    return pathname === base || pathname.startsWith(`${base}/`);
}
export async function getSpursUser(session = spurs()) {
    const store = await cookies();
    return session.verify(store.get(session.cookieName)?.value);
}
export async function requireSpursUser(returnTo = readEnv().APP_URL ?? '/', session = spurs()) {
    const user = await getSpursUser(session);
    if (!user)
        redirect(session.loginUrl(absoluteReturnTo(returnTo, readEnv().APP_URL)));
    return user;
}
export function createSpursProxy(options = {}) {
    const { publicPaths = [], apiPaths = ['/api/'] } = options;
    return async function spursProxy(request) {
        const { NextResponse } = await import('next/server');
        const { pathname } = request.nextUrl;
        if (publicPaths.some((p) => isPublicPath(pathname, p)))
            return NextResponse.next();
        const session = options.session ?? spurs();
        let user;
        try {
            user = await session.verify(request.cookies.get(session.cookieName)?.value);
        }
        catch {
            return NextResponse.json({ message: 'Authentication service unavailable.' }, { status: 503 });
        }
        if (user)
            return NextResponse.next();
        if (apiPaths.some((p) => isPublicPath(pathname, p))) {
            return NextResponse.json({ message: 'Unauthenticated.' }, { status: 401 });
        }
        const appUrl = options.appUrl ?? readEnv().APP_URL;
        const returnTo = appUrl
            ? `${appUrl.replace(/\/+$/, '')}${pathname}${request.nextUrl.search ?? ''}`
            : request.url;
        return NextResponse.redirect(session.loginUrl(returnTo));
    };
}
//# sourceMappingURL=next.js.map