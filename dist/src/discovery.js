import { SpursAuthError } from './errors.js';
import { normalizeIssuer, record } from './util.js';
export async function fetchMetadata(issuer, fetchFn) {
    const base = normalizeIssuer(issuer);
    let response;
    try {
        response = await fetchFn(`${base}/.well-known/openid-configuration`, {
            headers: { Accept: 'application/json' },
        });
    }
    catch (cause) {
        throw new SpursAuthError('discovery_failed', `Could not reach ${base}.`, undefined, { cause });
    }
    if (!response.ok) {
        throw new SpursAuthError('discovery_failed', `Discovery failed with status ${response.status}.`, response.status);
    }
    let document;
    try {
        document = await response.json();
    }
    catch (cause) {
        throw new SpursAuthError('discovery_failed', 'Discovery returned invalid JSON.', undefined, { cause });
    }
    const meta = record(document);
    if (!meta || typeof meta.issuer !== 'string') {
        throw new SpursAuthError('discovery_failed', 'Discovery returned an invalid document.');
    }
    if (normalizeIssuer(meta.issuer) !== base) {
        throw new SpursAuthError('issuer_mismatch', `Discovery issuer "${meta.issuer}" does not match "${base}".`);
    }
    for (const field of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) {
        if (typeof meta[field] !== 'string') {
            throw new SpursAuthError('discovery_failed', `Discovery document has no ${field}.`);
        }
    }
    return meta;
}
export function metadataLoader(issuer, fetchFn) {
    let pending;
    return () => {
        pending ??= fetchMetadata(issuer, fetchFn).catch((error) => {
            pending = undefined;
            throw error;
        });
        return pending;
    };
}
//# sourceMappingURL=discovery.js.map