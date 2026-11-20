import { Router, Request, Response } from 'express';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { pool } from '../db/pool';
import { requireAuth } from '../middleware/auth';
import { encryptTotpSecret, decryptTotpSecret } from '../services/totpCrypto';
import { authRateLimiter } from '../middleware/rateLimiter';
import { logAuditEvent } from '../services/auditLogger';

export const twoFactorRouter = Router();

twoFactorRouter.use(authRateLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_development_secret_not_for_prod';

// Allow 2 steps (±60 seconds) tolerance for mobile device clock drift
authenticator.options = { window: 2 };

function hashBackupCode(code: string): string {
  return crypto.createHash('sha256').update(code.trim().toUpperCase()).digest('hex');
}

/**
 * GET /api/auth/2fa/status
 * Check if 2FA is currently enabled for the authenticated user
 */
twoFactorRouter.get('/status', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  try {
    const result = await pool.query(
      'SELECT totp_enabled, cardinality(backup_codes) as backup_count FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    const row = result.rows[0];
    res.status(200).json({
      enabled: Boolean(row.totp_enabled),
      backupCodesRemaining: parseInt(row.backup_count || '0', 10),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database error';
    res.status(500).json({ error: 'Failed to retrieve 2FA status.', details: msg });
  }
});

/**
 * POST /api/auth/2fa/setup
 * Generates a new TOTP secret, encrypts it with TOTP_ENC_KEY, and returns QR code data URL.
 */
twoFactorRouter.post('/setup', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const email = req.user!.email;

  try {
    // Generate high-entropy secret (Base32 encoded)
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(email, 'Vaultify', secret);
    const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

    // Encrypt TOTP secret at rest with AES-256-GCM using TOTP_ENC_KEY
    const { ciphertext, iv } = encryptTotpSecret(secret);

    // Store encrypted secret temporarily pending verification
    await pool.query(
      `UPDATE users
       SET totp_secret = $1, totp_iv = $2, totp_enabled = FALSE
       WHERE id = $3`,
      [ciphertext, iv, userId]
    );

    await logAuditEvent({
      userId,
      eventType: '2FA_SETUP_INITIATED',
      req,
    });

    res.status(200).json({
      secret,
      qrCode: qrCodeDataUrl,
      otpauth,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '2FA setup error';
    res.status(500).json({ error: 'Failed to initiate 2FA setup.', details: msg });
  }
});

/**
 * POST /api/auth/2fa/verify
 * Handles two flows:
 * 1. Step-up login verification (Bearer preAuthToken) -> Returns full 24h JWT.
 * 2. Enabling 2FA on account (Bearer standard JWT) -> Confirms code, generates 8 backup codes, enables 2FA.
 * Supports both 6-digit TOTP codes and 8-character backup recovery codes!
 */
twoFactorRouter.post('/verify', async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication token required.' });
    return;
  }

  const token = authHeader.substring(7);

  // Accept code from either req.body.code or req.body.token, and sanitize
  const rawInput = req.body.code ?? req.body.token ?? '';
  const sanitizedInput = String(rawInput).replace(/[\s-]+/g, '').trim();

  if (!sanitizedInput) {
    res.status(400).json({ error: 'Authentication code or backup code is required.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: string;
      email?: string;
      scope?: string;
    };

    const userRes = await pool.query(
      `SELECT id, email, totp_secret, totp_iv, totp_enabled, backup_codes
       FROM users WHERE id = $1`,
      [decoded.userId]
    );

    if (userRes.rows.length === 0) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const user = userRes.rows[0];

    if (!user.totp_secret || !user.totp_iv) {
      res.status(400).json({ error: '2FA has not been initiated for this account.' });
      return;
    }

    let isAuthorized = false;
    let usedBackupCode = false;

    // Check 1: 6-digit TOTP code
    if (/^\d{6}$/.test(sanitizedInput)) {
      try {
        const plainSecret = decryptTotpSecret(user.totp_secret, user.totp_iv);
        isAuthorized = authenticator.check(sanitizedInput, plainSecret);
      } catch (decErr) {
        console.error('[2FA] Decryption error on TOTP secret:', decErr);
      }
    }

    // Check 2: Backup Recovery Code fallback (8 alphanumeric characters)
    if (!isAuthorized && Array.isArray(user.backup_codes) && user.backup_codes.length > 0) {
      const inputHash = hashBackupCode(sanitizedInput);
      const codeIndex = user.backup_codes.indexOf(inputHash);

      if (codeIndex !== -1) {
        isAuthorized = true;
        usedBackupCode = true;

        // Consume used backup code atomically
        await pool.query(
          `UPDATE users
           SET backup_codes = array_remove(backup_codes, $1)
           WHERE id = $2`,
          [inputHash, user.id]
        );

        await logAuditEvent({
          userId: user.id,
          eventType: '2FA_BACKUP_CODE_USED',
          req,
          details: { codesRemaining: user.backup_codes.length - 1 },
        });
      }
    }

    if (!isAuthorized) {
      await logAuditEvent({
        userId: user.id,
        eventType: '2FA_VERIFICATION_FAILED',
        req,
      });
      res.status(401).json({ error: 'Invalid or expired authentication code. Please check your authenticator clock or use a backup code.' });
      return;
    }

    // Flow 1: Step-up login verification
    if (decoded.scope === 'pre-auth') {
      const fullToken = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      await logAuditEvent({
        userId: user.id,
        eventType: 'LOGIN_2FA_SUCCESS',
        req,
        details: { usedBackupCode },
      });

      res.status(200).json({
        message: 'Two-factor authentication successful.',
        token: fullToken,
        user: { id: user.id, email: user.email },
      });
      return;
    }

    // Flow 2: Enabling 2FA for the first time
    // Generate 8 fresh backup recovery codes
    const plainBackupCodes: string[] = [];
    const hashedBackupCodes: string[] = [];

    for (let i = 0; i < 8; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // 8 chars (e.g. A1B2C3D4)
      plainBackupCodes.push(code);
      hashedBackupCodes.push(hashBackupCode(code));
    }

    await pool.query(
      `UPDATE users
       SET totp_enabled = TRUE,
           backup_codes = $1,
           updated_at = NOW()
       WHERE id = $2`,
      [hashedBackupCodes, user.id]
    );

    await logAuditEvent({
      userId: user.id,
      eventType: '2FA_ENABLED',
      req,
      details: { backupCodesGenerated: 8 },
    });

    res.status(200).json({
      message: 'Two-factor authentication successfully enabled.',
      enabled: true,
      backupCodes: plainBackupCodes,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Verification failed';
    res.status(401).json({ error: 'Token invalid or verification failed.', details: msg });
  }
});

/**
 * POST /api/auth/2fa/disable
 * Disables 2FA after verifying the current TOTP code or a backup code.
 */
twoFactorRouter.post('/disable', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const rawInput = req.body.code ?? req.body.token ?? '';
  const sanitizedInput = String(rawInput).replace(/[\s-]+/g, '').trim();

  if (!sanitizedInput) {
    res.status(400).json({ error: 'Current 6-digit TOTP code or backup code is required to disable 2FA.' });
    return;
  }

  try {
    const userRes = await pool.query(
      `SELECT totp_secret, totp_iv, totp_enabled, backup_codes FROM users WHERE id = $1`,
      [userId]
    );

    if (userRes.rows.length === 0 || !userRes.rows[0].totp_enabled) {
      res.status(400).json({ error: '2FA is not enabled on this account.' });
      return;
    }

    const user = userRes.rows[0];
    let isAuthorized = false;

    // Check TOTP
    if (/^\d{6}$/.test(sanitizedInput)) {
      try {
        const plainSecret = decryptTotpSecret(user.totp_secret, user.totp_iv);
        isAuthorized = authenticator.check(sanitizedInput, plainSecret);
      } catch (e) {
        console.error('[2FA] Decryption error:', e);
      }
    }

    // Check Backup Code
    if (!isAuthorized && Array.isArray(user.backup_codes)) {
      const inputHash = hashBackupCode(sanitizedInput);
      if (user.backup_codes.includes(inputHash)) {
        isAuthorized = true;
      }
    }

    if (!isAuthorized) {
      res.status(401).json({ error: 'Invalid authentication code or backup code.' });
      return;
    }

    await pool.query(
      `UPDATE users
       SET totp_enabled = FALSE,
           totp_secret = NULL,
           totp_iv = NULL,
           backup_codes = '{}',
           updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );

    await logAuditEvent({
      userId,
      eventType: '2FA_DISABLED',
      req,
    });

    res.status(200).json({ message: '2FA has been disabled successfully.' });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Disable 2FA error';
    res.status(500).json({ error: 'Failed to disable 2FA.', details: msg });
  }
});
