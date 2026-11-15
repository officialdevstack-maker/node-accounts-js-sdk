import { SpursAuthError } from './errors.js';
import { base64urlEncode } from './util.js';
export function randomString(byteLength = 32) {
    if (!Number.isInteger(byteLength) || byteLength < 1 || byteLength > 128) {
        throw new SpursAuthError('invalid_argument', 'Random string length must be between 1 and 128 bytes.');
    }
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64urlEncode(bytes);
}
export const createVerifier = () => randomString(48);
export async function createChallenge(verifier) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64urlEncode(new Uint8Array(digest));
}
//# sourceMappingURL=pkce.js.map