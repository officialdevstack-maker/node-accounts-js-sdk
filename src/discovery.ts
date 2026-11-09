import { SpursAuthError } from './errors.js';
import { normalizeIssuer, record } from './util.js';

export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  authorization_response_iss_parameter_supported?: boolean;
  [key: string]: unknown;
}

export async function fetchMetadata(issuer: string, fetchFn: typeof fetch): Promise<ProviderMetadata> {
  const base = normalizeIssuer(issuer);
  let response: Response;
  try {
    response = await fetchFn(`${base}/.well-known/openid-configuration`, {
      headers: { Accept: 'application/json' },
    });
  } catch (cause) {
    throw new SpursAuthError('discovery_failed', `Could not reach ${base}.`, undefined, { cause });
  }
  if (!response.ok) {
    throw new SpursAuthError('discovery_failed', `Discovery failed with status ${response.status}.`, response.status);
  }

  let document: unknown;
  try {
    document = await response.json();
  } catch (cause) {
    throw new SpursAuthError('discovery_failed', 'Discovery returned invalid JSON.', undefined, { cause });
  }
  const meta = record(document) as ProviderMetadata | null;
  if (!meta || typeof meta.issuer !== 'string') {
    throw new SpursAuthError('discovery_failed', 'Discovery returned an invalid document.');
  }
  if (normalizeIssuer(meta.issuer) !== base) {
    throw new SpursAuthError('issuer_mismatch', `Discovery issuer "${meta.issuer}" does not match "${base}".`);
  }
  for (const field of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as const) {
    if (typeof meta[field] !== 'string') {
      throw new SpursAuthError('discovery_failed', `Discovery document has no ${field}.`);
    }
  }
  return meta;
}

export function metadataLoader(issuer: string, fetchFn: typeof fetch): () => Promise<ProviderMetadata> {
  let pending: Promise<ProviderMetadata> | undefined;
  return () => {
    pending ??= fetchMetadata(issuer, fetchFn).catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
    return pending;
  };
}
