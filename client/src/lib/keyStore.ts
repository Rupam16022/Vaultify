/**
 * In-memory non-extractable CryptoKey storage.
 *
 * Architectural Decision:
 * Redux Toolkit requires all state values to be strictly serializable.
 * Web Crypto CryptoKey instances are non-serializable native browser handles.
 * Furthermore, storing the CryptoKey in a closure rather than global state or
 * Web Storage (localStorage/sessionStorage) prevents accidental stringification,
 * memory dumps, or cross-tab access.
 */

let inMemoryEncryptionKey: CryptoKey | null = null;

export const keyStore = {
  setKey(key: CryptoKey): void {
    inMemoryEncryptionKey = key;
  },

  getKey(): CryptoKey | null {
    return inMemoryEncryptionKey;
  },

  clearKey(): void {
    inMemoryEncryptionKey = null;
  },

  hasKey(): boolean {
    return inMemoryEncryptionKey !== null;
  },
};
