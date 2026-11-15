import type { AuthListener, AuthorizationRequest, AuthorizationRequestOptions, CallbackResult, IdTokenClaims, SignInOptions, SpursAuthOptions, TokenSet, UserClaims } from './types.js';
export declare class SpursAuth {
    readonly options: SpursAuthOptions & {
        issuer: string;
        scope: string;
        leewaySeconds: number;
        refreshSkewSeconds: number;
        cleanUrl: boolean;
    };
    private readonly fetchFn;
    private readonly tokenStore;
    private readonly requestStore;
    private readonly prefix;
    private readonly metadata;
    private readonly jwks;
    private readonly listeners;
    private readonly callbacks;
    private refreshing;
    private cache;
    constructor(options: SpursAuthOptions);
    dispose(): void;
    createAuthorizationRequest(options?: AuthorizationRequestOptions): Promise<AuthorizationRequest>;
    exchangeCode(callback: string | URL | URLSearchParams, expected: {
        state: string;
        nonce: string;
        codeVerifier: string;
        redirectUri?: string;
    }): Promise<TokenSet>;
    refresh(refreshToken: string): Promise<TokenSet>;
    userinfo(accessToken: string): Promise<UserClaims>;
    revoke(token: string): Promise<void>;
    endSessionUrl(options: {
        idTokenHint: string;
        postLogoutRedirectUri?: string;
        state?: string;
    }): Promise<string>;
    signIn(options?: SignInOptions): Promise<void>;
    isCallback(url?: string | URL): boolean;
    handleRedirectCallback(url?: string | URL): Promise<CallbackResult>;
    getTokens(): TokenSet | null;
    getUser(): IdTokenClaims | null;
    isAuthenticated(): boolean;
    getAccessToken(options?: {
        forceRefresh?: boolean;
    }): Promise<string>;
    refreshSession(): Promise<TokenSet>;
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
    fetchUserInfo(): Promise<UserClaims>;
    signOut(): Promise<void>;
    signOutEverywhere(options?: {
        postLogoutRedirectUri?: string;
        state?: string;
    }): Promise<void>;
    onChange(listener: AuthListener): () => void;
    private scopeFor;
    private expiring;
    private processCallback;
    private doRefresh;
    private withLock;
    private applyClientAuth;
    private tokenRequest;
    private send;
    private toTokenSet;
    private verifyIdToken;
    private get sessionKey();
    private load;
    private save;
    private clear;
    private emit;
    private readonly onStorage;
    private savePending;
    private takePending;
    private location;
    private currentPath;
    private safeReturnTo;
    private navigate;
    private cleanAddressBar;
}
//# sourceMappingURL=client.d.ts.map