export function base64urlEncode(bytes) {
    let binary = '';
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function base64urlDecode(input) {
    if (!/^[A-Za-z0-9_-]*$/.test(input))
        throw new Error('Invalid base64url input.');
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
export const normalizeIssuer = (issuer) => issuer.trim().replace(/\/+$/, '');
export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const text = (value) => typeof value === 'string' && value !== '' ? value : undefined;
export function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
//# sourceMappingURL=util.js.map