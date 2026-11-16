import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  deriveKeys,
  encryptVault,
  decryptVault,
  generatePassword,
  sha1,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes
} from './crypto';

describe('Vaultify Cryptographic Engine Tests', () => {
  describe('Salt Generation', () => {
    it('generates a 16-byte (32 hex char) cryptographically secure salt', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();

      expect(salt1).toHaveLength(32);
      expect(salt2).toHaveLength(32);
      expect(salt1).not.toBe(salt2); // Uniqueness check

      const bytes = hexToBytes(salt1);
      expect(bytes.length).toBe(16);
    });
  });

  describe('Key Derivation (PBKDF2 + HKDF)', () => {
    it('derives independent Auth Key and non-extractable Encryption Key', async () => {
      const password = 'Correct-Horse-Battery-Staple-987!';
      const salt = generateSalt();

      const { authKeyHex, encryptionKey } = await deriveKeys(password, salt);

      // Auth Key should be a 256-bit (64 hex characters) string
      expect(authKeyHex).toHaveLength(64);
      expect(/^[0-9a-f]{64}$/.test(authKeyHex)).toBe(true);

      // Encryption Key should be non-extractable AES-GCM CryptoKey
      expect(encryptionKey.type).toBe('secret');
      expect(encryptionKey.extractable).toBe(false);
      expect(encryptionKey.algorithm.name).toBe('AES-GCM');
      // @ts-expect-error algorithm length property on AesKeyAlgorithm
      expect(encryptionKey.algorithm.length).toBe(256);
      expect(encryptionKey.usages).toContain('encrypt');
      expect(encryptionKey.usages).toContain('decrypt');
    });

    it('derives deterministic keys for the same password and salt', async () => {
      const password = 'Deterministic-Password-123';
      const salt = '0123456789abcdef0123456789abcdef';

      const keys1 = await deriveKeys(password, salt);
      const keys2 = await deriveKeys(password, salt);

      expect(keys1.authKeyHex).toBe(keys2.authKeyHex);
    });

    it('derives completely distinct keys if salt differs', async () => {
      const password = 'IdenticalPassword123!';
      const salt1 = generateSalt();
      const salt2 = generateSalt();

      const keys1 = await deriveKeys(password, salt1);
      const keys2 = await deriveKeys(password, salt2);

      expect(keys1.authKeyHex).not.toBe(keys2.authKeyHex);
    });

    it('derives completely distinct keys if password differs', async () => {
      const salt = generateSalt();
      const keys1 = await deriveKeys('Password-A-123!', salt);
      const keys2 = await deriveKeys('Password-B-123!', salt);

      expect(keys1.authKeyHex).not.toBe(keys2.authKeyHex);
    });
  });

  describe('Authenticated Encryption & Decryption (AES-256-GCM)', () => {
    it('successfully performs encrypt -> decrypt round trip', async () => {
      const password = 'Super-Secret-Master-Password!';
      const salt = generateSalt();
      const { encryptionKey } = await deriveKeys(password, salt);

      const vaultData = [
        {
          id: 'item-1',
          title: 'GitHub',
          username: 'sec-eng@example.com',
          password: 'Password123!',
          url: 'https://github.com',
          notes: 'Production account with MFA'
        },
        {
          id: 'item-2',
          title: 'AWS Console',
          username: 'cloud-admin',
          password: 'AnotherSecurePassword#99',
          url: 'https://aws.amazon.com',
          notes: 'Root account'
        }
      ];

      // Encrypt
      const payload = await encryptVault(vaultData, encryptionKey);
      expect(payload.ciphertext).toBeDefined();
      expect(payload.iv).toBeDefined();

      // Decrypt
      const decrypted = await decryptVault<typeof vaultData>(
        payload.ciphertext,
        payload.iv,
        encryptionKey
      );

      expect(decrypted).toEqual(vaultData);
    });

    it('fails to decrypt with the wrong key', async () => {
      const salt = generateSalt();
      const { encryptionKey: correctKey } = await deriveKeys('CorrectPassword123!', salt);
      const { encryptionKey: wrongKey } = await deriveKeys('WrongPassword999!', salt);

      const secretData = { secretToken: 'XYZ-123-SECRET' };
      const payload = await encryptVault(secretData, correctKey);

      // Attempt decryption with wrong key -> must reject (OperationError / tag mismatch)
      await expect(
        decryptVault(payload.ciphertext, payload.iv, wrongKey)
      ).rejects.toThrow();
    });

    it('fails to decrypt if ciphertext is tampered with', async () => {
      const salt = generateSalt();
      const { encryptionKey } = await deriveKeys('SecurePassword!', salt);

      const secretData = { bankAccount: '1234-5678-9012' };
      const payload = await encryptVault(secretData, encryptionKey);

      // Tamper with ciphertext by altering characters
      const rawBytes = base64ToBytes(payload.ciphertext);
      rawBytes[5] ^= 0xff; // Flip bits
      const tamperedCiphertext = bytesToBase64(rawBytes);

      // AES-GCM integrity check must detect the tampering and fail
      await expect(
        decryptVault(tamperedCiphertext, payload.iv, encryptionKey)
      ).rejects.toThrow();
    });

    it('fails to decrypt if IV is tampered with', async () => {
      const salt = generateSalt();
      const { encryptionKey } = await deriveKeys('SecurePassword!', salt);

      const payload = await encryptVault({ message: 'Hello World' }, encryptionKey);

      // Tamper with IV
      const ivBytes = base64ToBytes(payload.iv);
      ivBytes[0] ^= 0x01; // Flip bit
      const tamperedIv = bytesToBase64(ivBytes);

      await expect(
        decryptVault(payload.ciphertext, tamperedIv, encryptionKey)
      ).rejects.toThrow();
    });

    it('generates unique IVs on every encryption (IV uniqueness)', async () => {
      const salt = generateSalt();
      const { encryptionKey } = await deriveKeys('Unique-IV-Test!', salt);
      const data = { test: true };

      const seenIVs = new Set<string>();
      const iterations = 50;

      for (let i = 0; i < iterations; i++) {
        const payload = await encryptVault(data, encryptionKey);
        expect(seenIVs.has(payload.iv)).toBe(false);
        seenIVs.add(payload.iv);
      }

      expect(seenIVs.size).toBe(iterations);
    });
  });

  describe('Password Generator with Rejection Sampling', () => {
    it('generates passwords of specified length', () => {
      for (const len of [12, 20, 32, 64]) {
        const pwd = generatePassword({ length: len });
        expect(pwd).toHaveLength(len);
      }
    });

    it('includes characters from all requested character classes', () => {
      const pwd = generatePassword({
        length: 24,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
      });

      expect(/[A-Z]/.test(pwd)).toBe(true);
      expect(/[a-z]/.test(pwd)).toBe(true);
      expect(/[0-9]/.test(pwd)).toBe(true);
      expect(/[!@#$%^&*()-_=+[\]{}|;:,.<>?]/.test(pwd)).toBe(true);
    });

    it('throws error on invalid length', () => {
      expect(() => generatePassword({ length: 5 })).toThrow();
      expect(() => generatePassword({ length: 200 })).toThrow();
    });
  });

  describe('SHA-1 Helper for HIBP k-Anonymity', () => {
    it('computes correct uppercase hex SHA-1 digest', async () => {
      // Known test vector: SHA-1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
      const hash = await sha1('password');
      expect(hash).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
    });

    it('supports 5-character prefix extraction for k-Anonymity', async () => {
      const hash = await sha1('password');
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      expect(prefix).toBe('5BAA6');
      expect(suffix).toBe('1E4C9B93F3F0682250B6CF8331B7EE68FD8');
    });
  });

  describe('Binary Conversion Helpers', () => {
    it('correctly converts between bytes and hex', () => {
      const original = new Uint8Array([0x00, 0x0f, 0x10, 0xab, 0xff]);
      const hex = bytesToHex(original);
      expect(hex).toBe('000f10abff');
      const back = hexToBytes(hex);
      expect(back).toEqual(original);
    });

    it('correctly converts between bytes and base64', () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const b64 = bytesToBase64(original);
      expect(b64).toBe('SGVsbG8=');
      const back = base64ToBytes(b64);
      expect(back).toEqual(original);
    });
  });
});
