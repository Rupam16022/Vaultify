import crypto from 'crypto';

const RAW_KEY = process.env.TOTP_ENC_KEY || 'default_totp_encryption_key_32_bytes_vaultify_2026';
// Derive consistent 32-byte key for AES-256-GCM
const TOTP_KEY = crypto.createHash('sha256').update(RAW_KEY).digest();

/**
 * Encrypts a TOTP secret at rest using AES-256-GCM with a fresh 12-byte IV.
 */
export function encryptTotpSecret(secret: string): { ciphertext: string; iv: string } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', TOTP_KEY, iv);

  let encrypted = cipher.update(secret, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();
  // Append 16-byte auth tag to ciphertext hex
  const fullCiphertext = encrypted + authTag.toString('hex');

  return {
    ciphertext: fullCiphertext,
    iv: iv.toString('hex'),
  };
}

/**
 * Decrypts a TOTP secret from AES-256-GCM ciphertext + IV.
 */
export function decryptTotpSecret(ciphertextHex: string, ivHex: string): string {
  const iv = Buffer.from(ivHex, 'hex');
  // Last 32 hex chars (16 bytes) is the GCM auth tag
  const tagLength = 32;
  const encryptedHex = ciphertextHex.slice(0, -tagLength);
  const authTagHex = ciphertextHex.slice(-tagLength);

  const decipher = crypto.createDecipheriv('aes-256-gcm', TOTP_KEY, iv);
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
