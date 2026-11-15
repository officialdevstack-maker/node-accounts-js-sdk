export interface ProviderMetadata {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri: string;
    introspection_endpoint?: string;
    revocation_endpoint?: string;
    end_session_endpoint?: string;
    authorization_response_iss_parameter_supported?: boolean;
    [key: string]: unknown;
}
export declare function fetchMetadata(issuer: string, fetchFn: typeof fetch): Promise<ProviderMetadata>;
export declare function metadataLoader(issuer: string, fetchFn: typeof fetch): () => Promise<ProviderMetadata>;
//# sourceMappingURL=discovery.d.ts.map