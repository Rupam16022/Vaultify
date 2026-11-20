import { Router, Request, Response } from 'express';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';
import { pool } from '../db/pool';
import { requireAuth } from '../middleware/auth';
import { encryptTotpSecret, decryptTotpSecret } from '../services/totpCrypto';
import { authRateLimiter } from '../middleware/rateLimiter';

export const twoFactorRouter = Router();

twoFactorRouter.use(authRateLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_development_secret_not_for_prod';

// Allow 1 step (±30 seconds) tolerance for minor client/server clock drift
authenticator.options = { window: 1 };

/**
 * GET /api/auth/2fa/status
 * Check if 2FA is currently enabled for the authenticated user
 */
twoFactorRouter.get('/status', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  try {
    const result = await pool.query('SELECT totp_enabled FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.status(200).json({ enabled: Boolean(result.rows[0].totp_enabled) });
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
 * 1. Step-up login verification (uses Bearer preAuthToken) -> Returns full 24h JWT.
 * 2. Enabling 2FA on account (uses Bearer standard JWT) -> Confirms code & enables 2FA.
 */
twoFactorRouter.post('/verify', async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication token required.' });
    return;
  }

  const token = authHeader.substring(7);
  const { code } = req.body;

  if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    res.status(400).json({ error: 'A valid 6-digit TOTP code is required.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: string;
      email?: string;
      scope?: string;
    };

    const userRes = await pool.query(
      `SELECT id, email, totp_secret, totp_iv, totp_enabled
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

    // Decrypt TOTP secret with TOTP_ENC_KEY
    const plainSecret = decryptTotpSecret(user.totp_secret, user.totp_iv);
    const isValid = authenticator.check(code.trim(), plainSecret);

    if (!isValid) {
      res.status(401).json({ error: 'Invalid or expired authentication code.' });
      return;
    }

    if (decoded.scope === 'pre-auth') {
      // Step-up login: Issue full JWT
      const fullToken = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.status(200).json({
        message: 'Two-factor authentication successful.',
        token: fullToken,
        user: { id: user.id, email: user.email },
      });
      return;
    }

    // Standard session: Confirming 2FA activation
    await pool.query(
      `UPDATE users SET totp_enabled = TRUE, updated_at = NOW() WHERE id = $1`,
      [user.id]
    );

    res.status(200).json({
      message: 'Two-factor authentication successfully enabled.',
      enabled: true,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Verification failed';
    res.status(401).json({ error: 'Token invalid or verification failed.', details: msg });
  }
});

/**
 * POST /api/auth/2fa/disable
 * Disables 2FA after verifying the current code.
 */
twoFactorRouter.post('/disable', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const { code } = req.body;

  if (!code || typeof code !== 'string') {
    res.status(400).json({ error: 'Current 6-digit TOTP code required to disable 2FA.' });
    return;
  }

  try {
    const userRes = await pool.query(
      `SELECT totp_secret, totp_iv, totp_enabled FROM users WHERE id = $1`,
      [userId]
    );

    if (userRes.rows.length === 0 || !userRes.rows[0].totp_enabled) {
      res.status(400).json({ error: '2FA is not enabled on this account.' });
      return;
    }

    const user = userRes.rows[0];
    const plainSecret = decryptTotpSecret(user.totp_secret, user.totp_iv);
    const isValid = authenticator.check(code.trim(), plainSecret);

    if (!isValid) {
      res.status(401).json({ error: 'Invalid authentication code.' });
      return;
    }

    await pool.query(
      `UPDATE users
       SET totp_enabled = FALSE, totp_secret = NULL, totp_iv = NULL, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );

    res.status(200).json({ message: '2FA has been disabled successfully.' });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Disable 2FA error';
    res.status(500).json({ error: 'Failed to disable 2FA.', details: msg });
  }
});
