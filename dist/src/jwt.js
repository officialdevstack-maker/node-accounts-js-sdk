import { SpursAuthError } from './errors.js';
import { base64urlDecode, nowSeconds, normalizeIssuer } from './util.js';
const invalid = (message) => new SpursAuthError('invalid_token', message);
export function decodeJwt(token) {
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => part === ''))
        throw invalid('Malformed token.');
    try {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        const header = JSON.parse(decoder.decode(base64urlDecode(parts[0])));
        const payload = JSON.parse(decoder.decode(base64urlDecode(parts[1])));
        if (header === null || typeof header !== 'object' ||
            payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
            throw new Error('JWT header or payload is not an object.');
        }
        return {
            header: header,
            payload: payload,
            signingInput: `${parts[0]}.${parts[1]}`,
            signature: base64urlDecode(parts[2]),
        };
    }
    catch (cause) {
        if (cause instanceof SpursAuthError)
            throw cause;
        throw new SpursAuthError('invalid_token', 'Malformed token.', undefined, { cause });
    }
}
export class JwksCache {
    getUri;
    fetchFn;
    ttlMs;
    keys = new Map();
    loadedAt = 0;
    loading;
    constructor(getUri, fetchFn, ttlMs = 10 * 60_000) {
        this.getUri = getUri;
        this.fetchFn = fetchFn;
        this.ttlMs = ttlMs;
    }
    async get(kid) {
        const age = Date.now() - this.loadedAt;
        const stale = age > this.ttlMs;
        if (!stale) {
            const hit = this.find(kid);
            if (hit)
                return hit;
        }
        if (stale || age > 30_000)
            await this.load();
        const key = this.find(kid);
        if (!key)
            throw invalid('The token was signed with an unknown key.');
        return key;
    }
    find(kid) {
        if (kid)
            return this.keys.get(kid);
        return this.keys.size === 1 ? this.keys.values().next().value : undefined;
    }
    load() {
        if (this.loading)
            return this.loading;
        const run = this.fetchKeys().finally(() => {
            this.loading = undefined;
        });
        this.loading = run;
        return run;
    }
    async fetchKeys() {
        let response;
        try {
            response = await this.fetchFn(await this.getUri(), { headers: { Accept: 'application/json' } });
        }
        catch (cause) {
            throw new SpursAuthError('jwks_unavailable', 'Could not download the signing keys.', undefined, { cause });
        }
        if (!response.ok) {
            throw new SpursAuthError('jwks_unavailable', `Signing keys request failed (${response.status}).`, response.status);
        }
        let body;
        try {
            body = await response.json();
        }
        catch (cause) {
            throw new SpursAuthError('jwks_unavailable', 'Signing keys returned invalid JSON.', undefined, { cause });
        }
        if (body === null || typeof body !== 'object' || !Array.isArray(body.keys)) {
            throw new SpursAuthError('jwks_unavailable', 'Signing keys returned an invalid document.');
        }
        const next = new Map();
        for (const candidate of body.keys) {
            if (candidate === null || typeof candidate !== 'object')
                continue;
            const jwk = candidate;
            if (jwk.kty !== 'RSA' ||
                typeof jwk.kid !== 'string' ||
                !jwk.kid ||
                (jwk.use && jwk.use !== 'sig') ||
                (jwk.alg && jwk.alg !== 'RS256')) {
                continue;
            }
            try {
                const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
                next.set(jwk.kid, key);
            }
            catch {
                continue;
            }
        }
        if (!next.size)
            throw new SpursAuthError('jwks_unavailable', 'No supported RS256 signing keys were found.');
        this.keys = next;
        this.loadedAt = Date.now();
    }
}
const cleanTyp = (typ) => typ?.replace(/^application\//i, '').toLowerCase();
export async function verifyJwt(token, jwks, options) {
    const jwt = decodeJwt(token);
    if (jwt.header.alg !== 'RS256')
        throw invalid('Unsupported signing algorithm.');
    if (options.typ && cleanTyp(jwt.header.typ) !== options.typ)
        throw invalid('Wrong token type.');
    const key = await jwks.get(jwt.header.kid);
    let valid;
    try {
        const signature = new Uint8Array(jwt.signature.length);
        signature.set(jwt.signature);
        valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, new TextEncoder().encode(jwt.signingInput));
    }
    catch (cause) {
        throw new SpursAuthError('invalid_token', 'Invalid token signature.', undefined, { cause });
    }
    if (!valid)
        throw invalid('Invalid token signature.');
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
    if (typeof claims.sub !== 'string' || claims.sub === '')
        throw invalid('Token has no subject.');
    if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp + leeway < now) {
        throw invalid('Token has expired.');
    }
    if (claims.nbf !== undefined &&
        (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf) || claims.nbf - leeway > now)) {
        throw invalid('Token is not valid yet.');
    }
    return jwt;
}
//# sourceMappingURL=jwt.js.map