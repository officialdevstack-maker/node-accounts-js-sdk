export type AccountType = 'user' | 'business' | 'developer';

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export type StorageKind = 'memory' | 'session' | 'local';

export interface JwtClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface UserClaims {
  sub: string;
  name?: string;
  account_type?: AccountType;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  [key: string]: unknown;
}

export interface IdTokenClaims extends JwtClaims, UserClaims {
  aud: string;
  auth_time?: number;
  at_hash?: string;
  nonce?: string;
}

export interface AccessTokenClaims extends JwtClaims {
  scope?: string;
  client_id?: string;
  grant_type?: 'client_credentials';
  gid?: number;
}

export interface TokenSet {
  accessToken: string;
  tokenType: 'Bearer';
  expiresAt: number;
  scope: string[];
  idToken?: string;
  refreshToken?: string;
  claims?: IdTokenClaims;
}

export interface SpursAuthOptions {
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri?: string;
  scope?: string;
  offlineAccess?: boolean;
  clientSecret?: string;
  storage?: StorageKind | StorageLike;
  requestStorage?: StorageLike;
  leewaySeconds?: number;
  refreshSkewSeconds?: number;
  cleanUrl?: boolean;
  fetch?: typeof fetch;
}

export interface SignInOptions {
  scope?: string;
  prompt?: 'none' | 'login' | 'consent';
  maxAge?: number;
  loginHint?: string;
  returnTo?: string;
  redirectUri?: string;
}

export type AuthorizationRequestOptions = Omit<SignInOptions, 'returnTo'>;

export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
}

export interface CallbackResult {
  user: IdTokenClaims;
  tokens: TokenSet;
  returnTo: string;
}

export type AuthListener = (tokens: TokenSet | null) => void;
