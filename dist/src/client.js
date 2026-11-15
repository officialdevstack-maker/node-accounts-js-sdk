import { metadataLoader } from './discovery.js';
import { SpursAuthError } from './errors.js';
import { JwksCache, verifyJwt } from './jwt.js';
import { createChallenge, createVerifier, randomString } from './pkce.js';
import { resolveStorage, storageError } from './storage.js';
import { base64urlEncode, nowSeconds, normalizeIssuer, record, text } from './util.js';
const DEFAULT_SCOPE = 'openid profile email';
const DEFAULT_ISSUER = 'https://node-accounts-backend.onrender.com/api/oidc';
const PENDING_TTL_MS = 15 * 60_000;
const CALLBACK_PARAMS = ['code', 'state', 'iss', 'error', 'error_description'];
const env = globalThis;
function isTokenSet(value) {
    const parsed = record(value);
    if (!parsed ||
        typeof parsed.accessToken !== 'string' ||
        parsed.tokenType !== 'Bearer' ||
        typeof parsed.expiresAt !== 'number' ||
        !Number.isFinite(parsed.expiresAt) ||
        !Array.isArray(parsed.scope) ||
        !parsed.scope.every((item) => typeof item === 'string') ||
        (parsed.idToken !== undefined && typeof parsed.idToken !== 'string') ||
        (parsed.refreshToken !== undefined && typeof parsed.refreshToken !== 'string')) {
        return false;
    }
    if (parsed.claims === undefined)
        return true;
    const claims = record(parsed.claims);
    return claims !== null &&
        typeof claims.sub === 'string' &&
        typeof claims.iss === 'string' &&
        (typeof claims.aud === 'string' || Array.isArray(claims.aud)) &&
        typeof claims.exp === 'number';
}
export class SpursAuth {
    options;
    fetchFn;
    tokenStore;
    requestStore;
    prefix;
    metadata;
    jwks;
    listeners = new Set();
    callbacks = new Map();
    refreshing;
    cache = { raw: null, value: null };
    constructor(options) {
        if (!options.clientId)
            throw new SpursAuthError('invalid_config', '`clientId` is required.');
        if (!options.redirectUri)
            throw new SpursAuthError('invalid_config', '`redirectUri` is required.');
        const issuer = options.issuer ?? DEFAULT_ISSUER;
        if (typeof issuer !== 'string' || !issuer.trim()) {
            throw new SpursAuthError('invalid_config', '`issuer` must be a non-empty string.');
        }
        if (options.leewaySeconds !== undefined && (!Number.isFinite(options.leewaySeconds) || options.leewaySeconds < 0)) {
            throw new SpursAuthError('invalid_config', '`leewaySeconds` must be a non-negative number.');
        }
        if (options.refreshSkewSeconds !== undefined &&
            (!Number.isFinite(options.refreshSkewSeconds) || options.refreshSkewSeconds < 0)) {
            throw new SpursAuthError('invalid_config', '`refreshSkewSeconds` must be a non-negative number.');
        }
        this.options = {
            ...options,
            issuer: normalizeIssuer(issuer),
            scope: options.scope ?? DEFAULT_SCOPE,
            leewaySeconds: options.leewaySeconds ?? 60,
            refreshSkewSeconds: options.refreshSkewSeconds ?? 30,
            cleanUrl: options.cleanUrl ?? true,
        };
        const fetchFn = options.fetch ?? globalThis.fetch?.bind(globalThis);
        if (!fetchFn)
            throw new SpursAuthError('invalid_config', 'No fetch available. Pass `fetch` in the options.');
        this.fetchFn = fetchFn;
        this.prefix = `spurs:${options.clientId}`;
        this.tokenStore = resolveStorage(options.storage, 'session');
        this.requestStore = options.requestStorage ?? resolveStorage('session', 'session');
        this.metadata = metadataLoader(this.options.issuer, this.fetchFn);
        this.jwks = new JwksCache(async () => (await this.metadata()).jwks_uri, this.fetchFn);
        env.addEventListener?.('storage', this.onStorage);
    }
    dispose() {
        env.removeEventListener?.('storage', this.onStorage);
        this.listeners.clear();
    }
    async createAuthorizationRequest(options = {}) {
        const meta = await this.metadata();
        const state = randomString(24);
        const nonce = randomString(24);
        const codeVerifier = createVerifier();
        const redirectUri = options.redirectUri ?? this.options.redirectUri;
        const url = new URL(meta.authorization_endpoint);
        url.searchParams.set('client_id', this.options.clientId);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', this.scopeFor(options.scope));
        url.searchParams.set('state', state);
        url.searchParams.set('nonce', nonce);
        url.searchParams.set('code_challenge', await createChallenge(codeVerifier));
        url.searchParams.set('code_challenge_method', 'S256');
        if (options.prompt)
            url.searchParams.set('prompt', options.prompt);
        if (options.maxAge !== undefined) {
            if (!Number.isSafeInteger(options.maxAge) || options.maxAge < 0) {
                throw new SpursAuthError('invalid_argument', '`maxAge` must be a non-negative integer.');
            }
            url.searchParams.set('max_age', String(options.maxAge));
        }
        if (options.loginHint !== undefined) {
            if (options.loginHint.length > 255) {
                throw new SpursAuthError('invalid_argument', '`loginHint` must be at most 255 characters.');
            }
            url.searchParams.set('login_hint', options.loginHint);
        }
        return { url: url.toString(), state, nonce, codeVerifier, redirectUri };
    }
    async exchangeCode(callback, expected) {
        const params = callback instanceof URLSearchParams
            ? callback
            : new URL(String(callback), 'http://localhost').searchParams;
        if (!expected.state || params.get('state') !== expected.state) {
            throw new SpursAuthError('state_mismatch', 'The sign-in response does not match the request. Start again.');
        }
        if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(expected.codeVerifier)) {
            throw new SpursAuthError('invalid_argument', 'The PKCE code verifier is malformed.');
        }
        const meta = await this.metadata();
        const iss = params.get('iss');
        if ((iss && normalizeIssuer(iss) !== this.options.issuer) ||
            (!iss && meta.authorization_response_iss_parameter_supported)) {
            throw new SpursAuthError('issuer_mismatch', 'The sign-in response came from an unexpected issuer.');
        }
        const error = params.get('error');
        if (error)
            throw new SpursAuthError(error, params.get('error_description') ?? error);
        const code = params.get('code');
        if (!code)
            throw new SpursAuthError('invalid_response', 'The sign-in response has no authorization code.');
        const data = await this.tokenRequest(new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: expected.redirectUri ?? this.options.redirectUri,
            code_verifier: expected.codeVerifier,
        }));
        return this.toTokenSet(data, { nonce: expected.nonce });
    }
    async refresh(refreshToken) {
        if (!refreshToken)
            throw new SpursAuthError('invalid_argument', '`refreshToken` is required.');
        const data = await this.tokenRequest(new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
        }));
        return this.toTokenSet(data, {});
    }
    async userinfo(accessToken) {
        if (!accessToken)
            throw new SpursAuthError('invalid_argument', '`accessToken` is required.');
        const meta = await this.metadata();
        const data = await this.send(meta.userinfo_endpoint, {
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        });
        if (typeof data.sub !== 'string')
            throw new SpursAuthError('invalid_response', 'UserInfo returned no subject.');
        return data;
    }
    async revoke(token) {
        if (!token)
            throw new SpursAuthError('invalid_argument', '`token` is required.');
        const meta = await this.metadata();
        if (!meta.revocation_endpoint)
            return;
        const body = new URLSearchParams({ token });
        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        this.applyClientAuth(headers, body);
        await this.send(meta.revocation_endpoint, { method: 'POST', headers, body });
    }
    async endSessionUrl(options) {
        const meta = await this.metadata();
        if (!meta.end_session_endpoint) {
            throw new SpursAuthError('unsupported', 'The server does not support sign-out.');
        }
        const url = new URL(meta.end_session_endpoint);
        url.searchParams.set('id_token_hint', options.idTokenHint);
        const target = options.postLogoutRedirectUri ?? this.options.postLogoutRedirectUri;
        if (target)
            url.searchParams.set('post_logout_redirect_uri', target);
        if (options.state)
            url.searchParams.set('state', options.state);
        return url.toString();
    }
    async signIn(options = {}) {
        const { returnTo, ...requestOptions } = options;
        const request = await this.createAuthorizationRequest(requestOptions);
        this.savePending(request.state, {
            codeVerifier: request.codeVerifier,
            nonce: request.nonce,
            redirectUri: request.redirectUri,
            returnTo: this.safeReturnTo(returnTo ?? this.currentPath()),
            createdAt: Date.now(),
        });
        this.navigate(request.url);
    }
    isCallback(url) {
        try {
            const target = new URL(String(url ?? this.location().href));
            const redirect = new URL(this.options.redirectUri);
            return target.origin === redirect.origin &&
                target.pathname === redirect.pathname &&
                target.searchParams.has('state') &&
                (target.searchParams.has('code') || target.searchParams.has('error'));
        }
        catch {
            return false;
        }
    }
    handleRedirectCallback(url) {
        const explicit = url !== undefined;
        const target = String(url ?? this.location().href);
        let run = this.callbacks.get(target);
        if (!run) {
            run = this.processCallback(target, !explicit && this.options.cleanUrl);
            this.callbacks.set(target, run);
        }
        return run;
    }
    getTokens() {
        return this.load();
    }
    getUser() {
        return this.load()?.claims ?? null;
    }
    isAuthenticated() {
        const session = this.load();
        return session !== null && (Boolean(session.refreshToken) || session.expiresAt > nowSeconds());
    }
    async getAccessToken(options = {}) {
        const session = this.load();
        if (!session)
            throw new SpursAuthError('not_authenticated', 'You are not signed in.');
        if (!options.forceRefresh && !this.expiring(session))
            return session.accessToken;
        return (await this.refreshSession()).accessToken;
    }
    refreshSession() {
        if (this.refreshing)
            return this.refreshing;
        const stale = this.load()?.accessToken;
        const run = this.withLock(() => this.doRefresh(stale)).finally(() => {
            this.refreshing = undefined;
        });
        this.refreshing = run;
        return run;
    }
    async fetch(input, init = {}) {
        const request = new Request(input, init);
        const sendWithToken = async (token) => {
            const authenticated = request.clone();
            authenticated.headers.set('Authorization', `Bearer ${token}`);
            return this.fetchFn(authenticated);
        };
        const first = await sendWithToken(await this.getAccessToken());
        if (first.status !== 401)
            return first;
        try {
            return await sendWithToken(await this.getAccessToken({ forceRefresh: true }));
        }
        catch {
            return first;
        }
    }
    async fetchUserInfo() {
        const info = await this.userinfo(await this.getAccessToken());
        const current = this.getUser();
        if (current && current.sub !== info.sub) {
            throw new SpursAuthError('invalid_response', 'UserInfo does not belong to the signed-in user.');
        }
        return info;
    }
    async signOut() {
        const session = this.load();
        this.clear();
        if (session?.refreshToken)
            await this.revoke(session.refreshToken);
    }
    async signOutEverywhere(options = {}) {
        const session = this.load();
        await this.signOut();
        if (!session?.idToken)
            return;
        this.navigate(await this.endSessionUrl({ idTokenHint: session.idToken, ...options }));
    }
    onChange(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }
    scopeFor(scope) {
        const set = new Set((scope ?? this.options.scope).split(/\s+/).filter(Boolean));
        set.add('openid');
        if (this.options.offlineAccess)
            set.add('offline_access');
        return [...set].join(' ');
    }
    expiring(session) {
        return session.expiresAt - this.options.refreshSkewSeconds <= nowSeconds();
    }
    async processCallback(target, clean) {
        const params = new URL(target).searchParams;
        const state = params.get('state');
        if (!state)
            throw new SpursAuthError('missing_state', 'The sign-in response has no state.');
        const pending = this.takePending(state);
        if (!pending)
            throw new SpursAuthError('state_mismatch', 'Unknown or expired sign-in request. Start again.');
        try {
            const tokens = await this.exchangeCode(params, {
                state,
                nonce: pending.nonce,
                codeVerifier: pending.codeVerifier,
                redirectUri: pending.redirectUri,
            });
            if (!tokens.claims)
                throw new SpursAuthError('invalid_response', 'The server returned no ID token.');
            this.save(tokens);
            return { user: tokens.claims, tokens, returnTo: pending.returnTo };
        }
        finally {
            if (clean)
                this.cleanAddressBar();
        }
    }
    async doRefresh(staleToken) {
        const current = this.load();
        if (!current)
            throw new SpursAuthError('not_authenticated', 'You are not signed in.');
        if (current.accessToken !== staleToken && !this.expiring(current))
            return current;
        if (!current.refreshToken) {
            this.clear();
            throw new SpursAuthError('no_refresh_token', 'Your session has expired. Sign in again.');
        }
        try {
            const data = await this.tokenRequest(new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: current.refreshToken,
            }));
            const next = await this.toTokenSet(data, { previous: current });
            this.save(next);
            return next;
        }
        catch (error) {
            if (error instanceof SpursAuthError && (error.code === 'invalid_grant' || error.code === 'invalid_client')) {
                this.clear();
            }
            throw error;
        }
    }
    withLock(task) {
        const locks = env.navigator?.locks;
        return locks
            ? locks.request(`${this.prefix}:refresh`, task).then((result) => result)
            : task();
    }
    applyClientAuth(headers, body) {
        const { clientId, clientSecret } = this.options;
        if (clientSecret) {
            headers.Authorization = `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`;
        }
        else {
            body.set('client_id', clientId);
        }
    }
    async tokenRequest(body) {
        const meta = await this.metadata();
        const headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
        };
        this.applyClientAuth(headers, body);
        return this.send(meta.token_endpoint, { method: 'POST', headers, body });
    }
    async send(url, init) {
        let response;
        try {
            response = await this.fetchFn(url, init);
        }
        catch (cause) {
            throw new SpursAuthError('network_error', 'Could not reach the Spurs server.', undefined, { cause });
        }
        let data = {};
        try {
            const parsed = record(await response.json());
            if (parsed)
                data = parsed;
        }
        catch {
            if (response.ok && response.status !== 204) {
                throw new SpursAuthError('invalid_response', 'The Spurs server returned invalid JSON.', response.status);
            }
        }
        if (!response.ok) {
            throw new SpursAuthError(text(data.error) ?? 'server_error', text(data.error_description) ?? text(data.message) ?? `Request failed with status ${response.status}.`, response.status);
        }
        return data;
    }
    async toTokenSet(data, context) {
        const accessToken = text(data.access_token);
        if (!accessToken)
            throw new SpursAuthError('invalid_response', 'The token response has no access_token.');
        if (data.token_type !== undefined && data.token_type !== 'Bearer') {
            throw new SpursAuthError('invalid_response', 'The token response uses an unsupported token type.');
        }
        const expiresIn = Number(data.expires_in);
        if (!Number.isFinite(expiresIn) || expiresIn <= 0) {
            throw new SpursAuthError('invalid_response', 'The token response has an invalid expires_in value.');
        }
        const responseScope = text(data.scope);
        const set = {
            accessToken,
            tokenType: 'Bearer',
            expiresAt: nowSeconds() + expiresIn,
            scope: responseScope?.split(/\s+/).filter(Boolean) ?? context.previous?.scope ?? [],
        };
        const idToken = text(data.id_token);
        if (idToken) {
            set.idToken = idToken;
            set.claims = await this.verifyIdToken(idToken, context.nonce, accessToken);
        }
        else if (context.previous?.idToken) {
            set.idToken = context.previous.idToken;
            if (context.previous.claims)
                set.claims = context.previous.claims;
        }
        else if (context.nonce !== undefined) {
            throw new SpursAuthError('invalid_response', 'The token response has no ID token.');
        }
        const refreshToken = text(data.refresh_token) ?? context.previous?.refreshToken;
        if (refreshToken)
            set.refreshToken = refreshToken;
        return set;
    }
    async verifyIdToken(idToken, nonce, accessToken) {
        const { payload } = await verifyJwt(idToken, this.jwks, {
            issuer: this.options.issuer,
            audience: this.options.clientId,
            leewaySeconds: this.options.leewaySeconds,
        });
        if (nonce !== undefined && payload.nonce !== nonce) {
            throw new SpursAuthError('nonce_mismatch', 'The ID token does not belong to this sign-in request.');
        }
        if (typeof payload.aud !== 'string') {
            throw new SpursAuthError('invalid_token', 'The ID token audience is invalid.');
        }
        if (payload.at_hash !== undefined) {
            if (typeof payload.at_hash !== 'string') {
                throw new SpursAuthError('invalid_token', 'The ID token access-token hash is invalid.');
            }
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)));
            const atHash = base64urlEncode(digest.subarray(0, 16));
            if (payload.at_hash !== atHash) {
                throw new SpursAuthError('invalid_token', 'The ID token does not match the access token.');
            }
        }
        return payload;
    }
    get sessionKey() {
        return `${this.prefix}:session`;
    }
    load() {
        let raw;
        try {
            raw = this.tokenStore.getItem(this.sessionKey);
        }
        catch (cause) {
            throw storageError(cause);
        }
        if (raw === this.cache.raw)
            return this.cache.value;
        let value = null;
        if (raw) {
            try {
                const parsed = JSON.parse(raw);
                if (isTokenSet(parsed))
                    value = parsed;
            }
            catch {
                value = null;
            }
        }
        this.cache = { raw, value };
        return value;
    }
    save(tokens) {
        const raw = JSON.stringify(tokens);
        try {
            this.tokenStore.setItem(this.sessionKey, raw);
        }
        catch (cause) {
            throw storageError(cause);
        }
        this.cache = { raw, value: tokens };
        this.emit();
    }
    clear() {
        try {
            this.tokenStore.removeItem(this.sessionKey);
        }
        catch (cause) {
            throw storageError(cause);
        }
        this.cache = { raw: null, value: null };
        this.emit();
    }
    emit() {
        const tokens = this.load();
        for (const listener of this.listeners)
            listener(tokens);
    }
    onStorage = (event) => {
        if (event.key === null || event.key === this.sessionKey)
            this.emit();
    };
    savePending(state, pending) {
        try {
            this.requestStore.setItem(`${this.prefix}:pending:${state}`, JSON.stringify(pending));
        }
        catch (cause) {
            throw storageError(cause);
        }
    }
    takePending(state) {
        const key = `${this.prefix}:pending:${state}`;
        let raw;
        try {
            raw = this.requestStore.getItem(key);
            this.requestStore.removeItem(key);
        }
        catch (cause) {
            throw storageError(cause);
        }
        if (!raw)
            return null;
        try {
            const pending = record(JSON.parse(raw));
            if (!pending ||
                typeof pending.codeVerifier !== 'string' ||
                typeof pending.nonce !== 'string' ||
                typeof pending.redirectUri !== 'string' ||
                typeof pending.returnTo !== 'string' ||
                typeof pending.createdAt !== 'number' ||
                !Number.isFinite(pending.createdAt) ||
                Date.now() - pending.createdAt > PENDING_TTL_MS ||
                pending.createdAt > Date.now()) {
                return null;
            }
            return pending;
        }
        catch {
            return null;
        }
    }
    location() {
        if (!env.location)
            throw new SpursAuthError('unsupported_environment', 'This method needs a browser.');
        return env.location;
    }
    currentPath() {
        const { pathname, search, hash } = this.location();
        return `${pathname}${search}${hash}`;
    }
    safeReturnTo(value) {
        const location = this.location();
        try {
            const target = new URL(value, location.href);
            if (target.origin !== location.origin) {
                throw new SpursAuthError('invalid_argument', '`returnTo` must be a same-origin URL.');
            }
            return `${target.pathname}${target.search}${target.hash}`;
        }
        catch (error) {
            if (error instanceof SpursAuthError)
                throw error;
            throw new SpursAuthError('invalid_argument', '`returnTo` must be a valid same-origin URL.', undefined, { cause: error });
        }
    }
    navigate(url) {
        if (!env.location) {
            throw new SpursAuthError('unsupported_environment', 'signIn() needs a browser. On a server use createAuthorizationRequest() and redirect yourself.');
        }
        env.location.assign(url);
    }
    cleanAddressBar() {
        if (!env.location || !env.history)
            return;
        const url = new URL(env.location.href);
        for (const key of CALLBACK_PARAMS)
            url.searchParams.delete(key);
        env.history.replaceState(env.history.state, '', `${url.pathname}${url.search}${url.hash}`);
    }
}
//# sourceMappingURL=client.js.map