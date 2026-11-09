import { SpursAuthError } from './errors.js';
import type { StorageKind, StorageLike } from './types.js';

export class MemoryStorage implements StorageLike {
  private readonly map = new Map<string, string>();

  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }

  removeItem(key: string): void {
    this.map.delete(key);
  }
}

export function resolveStorage(
  choice: StorageKind | StorageLike | undefined,
  fallback: StorageKind,
): StorageLike {
  if (choice && typeof choice === 'object') return choice;

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
    } catch {
      // Browser storage may be blocked; memory storage keeps the SDK usable.
    }
  } else {
    return new MemoryStorage();
  }
  return new MemoryStorage();
}

export function storageError(cause: unknown): SpursAuthError {
  return new SpursAuthError('storage_error', 'Could not access authentication storage.', undefined, { cause });
}
