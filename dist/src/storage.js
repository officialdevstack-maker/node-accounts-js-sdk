import { SpursAuthError } from './errors.js';
export class MemoryStorage {
    map = new Map();
    getItem(key) {
        return this.map.get(key) ?? null;
    }
    setItem(key, value) {
        this.map.set(key, value);
    }
    removeItem(key) {
        this.map.delete(key);
    }
}
export function resolveStorage(choice, fallback) {
    if (choice && typeof choice === 'object')
        return choice;
    const kind = choice ?? fallback;
    if (kind !== 'memory') {
        try {
            const store = kind === 'local' ? globalThis.localStorage : globalThis.sessionStorage;
            if (store) {
                const probe = '__spurs_probe__';
                store.setItem(probe, '1');
                store.removeItem(probe);
                return store;
            }
        }
        catch {
            // Browser storage may be blocked; memory storage keeps the SDK usable.
        }
    }
    else {
        return new MemoryStorage();
    }
    return new MemoryStorage();
}
export function storageError(cause) {
    return new SpursAuthError('storage_error', 'Could not access authentication storage.', undefined, { cause });
}
//# sourceMappingURL=storage.js.map