/**
 * ============================================================================
 * VAULTIFY ZERO-KNOWLEDGE CRYPTOGRAPHIC CORE ENGINE
 * ============================================================================
 *
 * CRYPTOGRAPHIC SECURITY PRINCIPLES & ARCHITECTURE:
 * 1. Zero-Knowledge: The master password NEVER leaves the client browser.
 *    The host server is treated as an untrusted ciphertext storage provider.
 * 2. 100% Native Web Crypto: Built strictly using the W3C Web Cryptography API
 *    (globalThis.crypto.subtle). Zero external crypto npm dependencies, preventing
 *    supply-chain vulnerabilities and malicious prototype pollution.
 * 3. Key Derivation & Domain Separation:
 *    - PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP recommendation)
 *      strengthens the user's password against offline GPU/ASIC brute-force attacks.
 *    - HKDF-SHA256 (RFC 5869) extracts and expands the PBKDF2 master key into two
 *      cryptographically independent subkeys:
 *        a) Auth Key ("vaultify-auth"): 256-bit key exported as hex to authenticate
 *           to the server over HTTPS. Even if the server DB or TLS is compromised,
 *           the Auth Key reveals zero information about the Encryption Key.
 *        b) Encryption Key ("vaultify-enc"): 256-bit AES-GCM key with
 *           `extractable: false`. It cannot be read or exported by any script or extension,
 *           and lives purely in browser memory during an active unlocked session.
 * 4. Authenticated Encryption:
 *    - AES-256-GCM provides both confidentiality and cryptographic integrity.
 *    - Every encryption generates a fresh, cryptographically secure 12-byte (96-bit) IV.
 *      Reusing an IV with the same AES-GCM key catastrophically breaks security.
 *    - The 128-bit authentication tag is automatically appended by AES-GCM, preventing
 *      ciphertext tampering or padding-oracle attacks.
 * 5. Rejection Sampling:
 *    - Password generation uses rejection sampling to eliminate modulo bias, ensuring
 *      every character from the specified alphabet has mathematically equal probability.
 * ============================================================================
 */

// Defensive check: Ensure Web Crypto Subtle is available
function getSubtleCrypto(): SubtleCrypto {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error('Web Crypto API (crypto.subtle) is not available in this environment.');
}

function getRandomValues(array: Uint8Array): Uint8Array {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    return globalThis.crypto.getRandomValues(array);
  }
  throw new Error('Web Crypto API (crypto.getRandomValues) is not available in this environment.');
}

/**
 * Binary conversion helpers: Uint8Array <-> Hex / Base64
 * Native implementations avoiding third-party dependencies.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length (must be even).');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Salt generation for PBKDF2.
 * Generates 16 cryptographically secure random bytes (128 bits).
 * 16 bytes is the NIST SP 800-132 recommended minimum salt size to prevent
 * precomputed rainbow table attacks.
 */
export function generateSalt(): string {
  const saltBytes = getRandomValues(new Uint8Array(16));
  return bytesToHex(saltBytes);
}

export interface DerivedKeys {
  /**
   * Auth Key (hex string): Sent to server for registration and login over HTTPS.
   * Derived via HKDF with info = "vaultify-auth".
   */
  authKeyHex: string;

  /**
   * Encryption Key (non-extractable CryptoKey): Kept in client memory only.
   * Derived via HKDF with info = "vaultify-enc".
   * Used for AES-256-GCM vault encryption and decryption.
   */
  encryptionKey: CryptoKey;
}

/**
 * Key Derivation Function (PBKDF2-HMAC-SHA256 + HKDF-SHA256)
 *
 * Steps:
 * 1. Import raw master password as PBKDF2 base key.
 * 2. PBKDF2 derivation with 600,000 iterations of HMAC-SHA256 and 16-byte user salt.
 *    Produces 256 bits of intermediate Master Key Material.
 * 3. Import intermediate Master Key Material as HKDF base key.
 * 4. HKDF Expand with domain separation:
 *    a) HKDF info = "vaultify-auth" -> 256-bit Auth Key (exported to hex).
 *    b) HKDF info = "vaultify-enc"  -> 256-bit AES-GCM Key (extractable: false).
 *
 * @param password Master password entered by user (never stored or transmitted).
 * @param saltHex Hex-encoded per-user salt.
 */
export async function deriveKeys(password: string, saltHex: string): Promise<DerivedKeys> {
  if (!password || password.length === 0) {
    throw new Error('Master password cannot be empty.');
  }
  const saltBytes = hexToBytes(saltHex);
  if (saltBytes.length < 16) {
    throw new Error('Salt must be at least 16 bytes.');
  }

  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // 1. Import password string as PBKDF2 key material
  const baseKey = await subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  // 2. Derive 256 bits (32 bytes) of Master Key Material using PBKDF2-HMAC-SHA256
  // 600,000 iterations conforms to the latest OWASP password storage recommendation
  // to ensure computational asymmetry favoring the defender against offline brute-force.
  const masterKeyBits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes as BufferSource,
      iterations: 600000,
      hash: 'SHA-256',
    },
    baseKey,
    256 // 256 bits
  );

  // 3. Import Master Key Material as HKDF master key
  const hkdfBaseKey = await subtle.importKey(
    'raw',
    masterKeyBits,
    { name: 'HKDF' },
    false,
    ['deriveBits', 'deriveKey']
  );

  // 4a. Derive Auth Key via HKDF-SHA256 with info="vaultify-auth"
  // Domain separation ensures the Auth Key cannot decrypt vault data
  // even if intercepted or leaked from the database.
  const authKeyBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0), // RFC 5869: Empty salt if master key already has high entropy
      info: encoder.encode('vaultify-auth'),
    },
    hkdfBaseKey,
    256 // 32 bytes
  );
  const authKeyHex = bytesToHex(new Uint8Array(authKeyBits));

  // 4b. Derive AES-256-GCM Encryption Key via HKDF-SHA256 with info="vaultify-enc"
  // CRITICAL: extractable is set to FALSE so the raw key bits cannot be read
  // by any JavaScript code, console inspection, or rogue browser extension.
  const encryptionKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('vaultify-enc'),
    },
    hkdfBaseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // NON-EXTRACTABLE
    ['encrypt', 'decrypt']
  );

  return { authKeyHex, encryptionKey };
}

export interface EncryptedPayload {
  /** Base64-encoded ciphertext including appended 128-bit authentication tag */
  ciphertext: string;
  /** Base64-encoded 12-byte initialization vector */
  iv: string;
}

/**
 * Encrypts arbitrary vault data using AES-256-GCM.
 *
 * Security requirements:
 * - Generates a fresh, cryptographically secure 12-byte (96-bit) IV on every invocation.
 * - AES-GCM computes a 128-bit authentication tag and appends it to the ciphertext.
 *
 * @param vaultData Any serializable JavaScript data (typically an array of vault items).
 * @param encryptionKey The non-extractable AES-GCM CryptoKey.
 */
export async function encryptVault(vaultData: unknown, encryptionKey: CryptoKey): Promise<EncryptedPayload> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();

  // Fresh 12-byte (96-bit) random IV per NIST SP 800-38D
  const iv = getRandomValues(new Uint8Array(12));

  // Serialize payload to JSON UTF-8 bytes
  const plaintext = encoder.encode(JSON.stringify(vaultData));

  // Encrypt using AES-GCM. SubtleCrypto automatically appends the 16-byte auth tag.
  const encryptedBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      tagLength: 128, // 128-bit authentication tag
    },
    encryptionKey,
    plaintext
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
    iv: bytesToBase64(iv),
  };
}

/**
 * Decrypts AES-256-GCM ciphertext payload and validates authenticity tag.
 *
 * If either the ciphertext, IV, or authentication tag has been tampered with,
 * or if an incorrect key is provided, subtle.decrypt() will reject with an error,
 * preventing corrupted or forged data from being parsed.
 *
 * @param ciphertext Base64-encoded ciphertext with tag.
 * @param iv Base64-encoded 12-byte IV.
 * @param encryptionKey The non-extractable AES-GCM CryptoKey.
 */
export async function decryptVault<T = unknown>(
  ciphertext: string,
  iv: string,
  encryptionKey: CryptoKey
): Promise<T> {
  const subtle = getSubtleCrypto();
  const decoder = new TextDecoder();

  const ciphertextBytes = base64ToBytes(ciphertext);
  const ivBytes = base64ToBytes(iv);

  if (ivBytes.length !== 12) {
    throw new Error('Invalid IV length: AES-GCM requires a 12-byte IV.');
  }

  // Decrypt and verify 128-bit GCM authentication tag
  const decryptedBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes as BufferSource,
      tagLength: 128,
    },
    encryptionKey,
    ciphertextBytes as BufferSource
  );

  const jsonString = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonString) as T;
}

export interface PasswordGeneratorOptions {
  length?: number;
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
}

/**
 * Cryptographically Secure Password Generator with Rejection Sampling.
 *
 * WHY REJECTION SAMPLING?
 * Using the modulo operator (e.g. `byte % alphabetLength`) introduces "modulo bias"
 * because 256 is rarely an exact multiple of the character pool size. Characters
 * near the start of the pool would be chosen with a higher probability.
 *
 * Rejection sampling calculates the largest multiple of `alphabetLength` that is <= 256:
 * `maxValid = 256 - (256 % alphabetLength)`.
 * Any sampled byte >= `maxValid` is rejected and resampled, guaranteeing that every
 * remaining value maps to an alphabet index with strictly equal (uniform) probability.
 */
export function generatePassword(options: PasswordGeneratorOptions = {}): string {
  const {
    length = 20,
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
  } = options;

  if (length < 8 || length > 128) {
    throw new Error('Password length must be between 8 and 128 characters.');
  }

  const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
  const NUMBERS = '0123456789';
  const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  const requiredPools: string[] = [];
  let fullAlphabet = '';

  if (includeUppercase) {
    requiredPools.push(UPPERCASE);
    fullAlphabet += UPPERCASE;
  }
  if (includeLowercase) {
    requiredPools.push(LOWERCASE);
    fullAlphabet += LOWERCASE;
  }
  if (includeNumbers) {
    requiredPools.push(NUMBERS);
    fullAlphabet += NUMBERS;
  }
  if (includeSymbols) {
    requiredPools.push(SYMBOLS);
    fullAlphabet += SYMBOLS;
  }

  if (fullAlphabet.length === 0) {
    throw new Error('At least one character set must be selected.');
  }

  /**
   * Helper: Sample a single character from a pool using unbiased rejection sampling.
   */
  function sampleCharUnbiased(pool: string): string {
    const poolSize = pool.length;
    const maxValid = 256 - (256 % poolSize);
    const randomByte = new Uint8Array(1);

    while (true) {
      getRandomValues(randomByte);
      const val = randomByte[0];
      if (val < maxValid) {
        return pool[val % poolSize];
      }
      // Value >= maxValid is rejected to eliminate modulo bias. Resample!
    }
  }

  const resultChars: string[] = [];

  // Guarantee at least one character from each enabled pool
  for (const pool of requiredPools) {
    resultChars.push(sampleCharUnbiased(pool));
  }

  // Fill remaining length from the complete alphabet
  while (resultChars.length < length) {
    resultChars.push(sampleCharUnbiased(fullAlphabet));
  }

  // Fisher-Yates shuffle with unbiased rejection sampling to randomize guaranteed positions
  for (let i = resultChars.length - 1; i > 0; i--) {
    const poolSize = i + 1;
    const maxValid = 256 - (256 % poolSize);
    const randomByte = new Uint8Array(1);
    let j: number;

    while (true) {
      getRandomValues(randomByte);
      const val = randomByte[0];
      if (val < maxValid) {
        j = val % poolSize;
        break;
      }
    }

    const temp = resultChars[i];
    resultChars[i] = resultChars[j];
    resultChars[j] = temp;
  }

  return resultChars.join('');
}

/**
 * Computes SHA-1 hash of a string using Web Crypto Subtle API.
 * Used for HaveIBeenPwned (HIBP) k-Anonymity breach detection:
 * The client sends ONLY the first 5 characters of this hash to api.pwnedpasswords.com/range/{prefix}.
 * The password itself and the rest of the hash never leave the browser.
 */
export async function sha1(text: string): Promise<string> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await subtle.digest('SHA-1', data);
  return bytesToHex(new Uint8Array(hashBuffer)).toUpperCase();
}
