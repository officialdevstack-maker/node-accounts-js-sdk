export interface ServiceClientOptions {
    issuer: string;
    clientId: string;
    clientSecret: string;
    scope?: string;
    fetch?: typeof fetch;
}
export declare function createServiceClient(options: ServiceClientOptions): {
    getToken: () => Promise<string>;
    fetch(url: string | URL, init?: RequestInit): Promise<Response>;
};
//# sourceMappingURL=service.d.ts.map