import { base64urlDecode, base64urlEncode, nowSeconds } from './util.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKey = (secret, usage) => crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
export function readCookie(header, name) {
    if (!header)
        return undefined;
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx < 0 || part.slice(0, idx).trim() !== name)
            continue;
        const raw = part.slice(idx + 1).trim();
        try {
            return decodeURIComponent(raw);
        }
        catch {
            return raw;
        }
    }
    return undefined;
}
export async function sealCookie(payload, secret, ttlSeconds) {
    const body = base64urlEncode(encoder.encode(JSON.stringify({ ...payload, exp: nowSeconds() + ttlSeconds })));
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret, 'sign'), encoder.encode(body)));
    return `${body}.${base64urlEncode(signature)}`;
}
export async function openCookie(value, secret) {
    if (!value)
        return null;
    const parts = value.split('.');
    if (parts.length !== 2)
        return null;
    try {
        const raw = base64urlDecode(parts[1]);
        const signature = new Uint8Array(raw.length);
        signature.set(raw);
        const valid = await crypto.subtle.verify('HMAC', await hmacKey(secret, 'verify'), signature, encoder.encode(parts[0]));
        if (!valid)
            return null;
        const payload = JSON.parse(decoder.decode(base64urlDecode(parts[0])));
        if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds())
            return null;
        return payload;
    }
    catch {
        return null;
    }
}
export function serializeCookie(name, value, options) {
    return [
        `${name}=${encodeURIComponent(value)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${options.maxAge}`,
        ...(options.secure ? ['Secure'] : []),
    ].join('; ');
}
//# sourceMappingURL=cookie-session.js.map