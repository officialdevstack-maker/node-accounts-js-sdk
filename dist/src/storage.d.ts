import { SpursAuthError } from './errors.js';
import type { StorageKind, StorageLike } from './types.js';
export declare class MemoryStorage implements StorageLike {
    private readonly map;
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}
export declare function resolveStorage(choice: StorageKind | StorageLike | undefined, fallback: StorageKind): StorageLike;
export declare function storageError(cause: unknown): SpursAuthError;
//# sourceMappingURL=storage.d.ts.map