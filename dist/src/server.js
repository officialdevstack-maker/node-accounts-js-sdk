import { metadataLoader } from './discovery.js';
import { SpursAuthError } from './errors.js';
import { JwksCache, verifyJwt } from './jwt.js';
import { normalizeIssuer, record } from './util.js';
export function getBearerToken(headers) {
    const header = headers.authorization;
    const value = Array.isArray(header) ? header[0] : header;
    return value?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() || null;
}
export function createVerifier(options) {
    if (!options.issuer)
        throw new SpursAuthError('invalid_config', '`issuer` is required.');
    if ((typeof options.audience === 'string' && !options.audience) ||
        (Array.isArray(options.audience) && (!options.audience.length || options.audience.some((item) => !item)))) {
        throw new SpursAuthError('invalid_config', '`audience` must contain at least one client id.');
    }
    if (options.leewaySeconds !== undefined && (!Number.isFinite(options.leewaySeconds) || options.leewaySeconds < 0)) {
        throw new SpursAuthError('invalid_config', '`leewaySeconds` must be a non-negative number.');
    }
    if (options.strict && (!options.introspectionClient?.clientId || !options.introspectionClient.clientSecret)) {
        throw new SpursAuthError('invalid_config', '`strict` requires confidential `introspectionClient` credentials.');
    }
    const issuer = normalizeIssuer(options.issuer);
    const fetchFn = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!fetchFn)
        throw new SpursAuthError('invalid_config', 'No fetch available. Pass `fetch` in the options.');
    const metadata = metadataLoader(issuer, fetchFn);
    const jwks = new JwksCache(async () => (await metadata()).jwks_uri, fetchFn);
    async function verify(token) {
        const { payload } = await verifyJwt(token, jwks, {
            issuer,
            audience: options.audience,
            leewaySeconds: options.leewaySeconds,
            typ: 'at+jwt',
        });
        const isClientToken = payload.grant_type === 'client_credentials';
        if (typeof payload.gid !== 'number' ||
            !Number.isSafeInteger(payload.gid) ||
            payload.gid < (isClientToken ? 0 : 1) ||
            (isClientToken && (payload.gid !== 0 || payload.sub !== payload.client_id)) ||
            typeof payload.client_id !== 'string' ||
            !payload.client_id ||
            (!isClientToken && payload.grant_type !== undefined)) {
            throw new SpursAuthError('invalid_token', 'This is not an access token.');
        }
        const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
        if (!audiences.includes(payload.client_id)) {
            throw new SpursAuthError('invalid_token', 'The access-token client does not match its audience.');
        }
        if (payload.scope !== undefined && typeof payload.scope !== 'string') {
            throw new SpursAuthError('invalid_token', 'The access-token scope is invalid.');
        }
        if (options.strict) {
            const meta = await metadata();
            if (!meta.introspection_endpoint) {
                throw new SpursAuthError('introspection_unavailable', 'The provider does not advertise an introspection endpoint.');
            }
            const credentials = options.introspectionClient;
            const body = new URLSearchParams({ token });
            const basic = btoa(`${encodeURIComponent(credentials.clientId)}:${encodeURIComponent(credentials.clientSecret)}`);
            let response;
            try {
                response = await fetchFn(meta.introspection_endpoint, {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${basic}`,
                        'Content-Type': 'application/x-www-form-urlencoded',
                        Accept: 'application/json',
                    },
                    body,
                });
            }
            catch (cause) {
                throw new SpursAuthError('introspection_unavailable', 'Could not reach the introspection endpoint.', undefined, {
                    cause,
                });
            }
            if (!response.ok) {
                throw new SpursAuthError('introspection_unavailable', `Introspection request failed (${response.status}).`, response.status);
            }
            let introspection;
            try {
                introspection = record(await response.json());
            }
            catch (cause) {
                throw new SpursAuthError('introspection_unavailable', 'Introspection returned invalid JSON.', undefined, {
                    cause,
                });
            }
            if (!introspection) {
                throw new SpursAuthError('introspection_unavailable', 'Introspection returned an invalid response.');
            }
            if (introspection.active !== true) {
                throw new SpursAuthError('invalid_token', 'Access has been revoked.');
            }
            if (introspection.sub !== payload.sub ||
                introspection.client_id !== payload.client_id ||
                introspection.aud !== payload.aud ||
                introspection.exp !== payload.exp) {
                throw new SpursAuthError('invalid_token', 'Introspection claims do not match the access token.');
            }
        }
        return {
            sub: payload.sub,
            principalType: isClientToken ? 'client' : 'user',
            clientId: payload.client_id,
            grantId: payload.gid,
            scopes: (payload.scope ?? '').split(/\s+/).filter(Boolean),
            claims: payload,
        };
    }
    function middleware(guard = {}) {
        const scopes = guard.scopes ?? [];
        if (scopes.some((scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
            throw new SpursAuthError('invalid_config', 'Required scopes must be valid OAuth scope tokens.');
        }
        return async (req, res, next) => {
            const token = getBearerToken(req.headers);
            if (!token) {
                res.setHeader('WWW-Authenticate', 'Bearer');
                res.status(401).json({ message: 'Unauthenticated.', error: 'invalid_request' });
                return;
            }
            try {
                const verified = await verify(token);
                const missing = scopes.filter((scope) => !verified.scopes.includes(scope));
                if (missing.length) {
                    res.setHeader('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${missing.join(' ')}"`);
                    res.status(403).json({
                        message: 'Insufficient scope.',
                        error: 'insufficient_scope',
                        scope: missing.join(' '),
                    });
                    return;
                }
                req.spurs = verified;
                next();
            }
            catch (error) {
                if (error instanceof SpursAuthError &&
                    error.code !== 'jwks_unavailable' &&
                    error.code !== 'discovery_failed' &&
                    error.code !== 'introspection_unavailable') {
                    res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
                    res.status(401).json({ message: 'Invalid or expired token.', error: 'invalid_token' });
                    return;
                }
                next(error);
            }
        };
    }
    return { verify, middleware };
}
//# sourceMappingURL=server.js.map