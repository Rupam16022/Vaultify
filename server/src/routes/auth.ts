import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from '../db/pool';
import { SaltRequestSchema, RegisterRequestSchema, LoginRequestSchema } from '../schemas/auth';
import { authRateLimiter } from '../middleware/rateLimiter';
import { requireAuth } from '../middleware/auth';
import { logAuditEvent } from '../services/auditLogger';

export const authRouter = Router();

// Apply auth rate limiter to all authentication routes
authRouter.use(authRateLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_development_secret_not_for_prod';
const SALT_PEPPER = process.env.SALT_PEPPER || 'vaultify_deterministic_salt_pepper_secret_2026';

// Dummy bcrypt hash for constant-time comparison on unknown email
const DUMMY_BCRYPT_HASH = '$2a$12$e80yqX4j2b2c4K3vL2r5uOx3b9sLz8sUjL8eY0oJk6iL7vM9m8cOq';

/**
 * POST /api/auth/salt
 * Prevents User Enumeration Attacks via deterministic HMAC-SHA256 salt
 */
authRouter.post('/salt', async (req: Request, res: Response) => {
  const parseResult = SaltRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { email } = parseResult.data;

  try {
    const result = await pool.query('SELECT salt FROM users WHERE LOWER(email) = $1', [email]);

    if (result.rows.length > 0) {
      res.status(200).json({ salt: result.rows[0].salt });
      return;
    }

    // Deterministic HMAC-SHA256 fake salt (16 bytes = 32 hex chars)
    const fakeSalt = crypto
      .createHmac('sha256', SALT_PEPPER)
      .update(email)
      .digest('hex')
      .slice(0, 32);

    res.status(200).json({ salt: fakeSalt });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database query error';
    res.status(500).json({ error: 'Failed to retrieve salt.', details: msg });
  }
});

/**
 * POST /api/auth/register
 */
authRouter.post('/register', async (req: Request, res: Response) => {
  const parseResult = RegisterRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { email, salt, authKey } = parseResult.data;

  try {
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email]);
    if (existing.rows.length > 0) {
      res.status(409).json({ error: 'An account with this email address already exists.' });
      return;
    }

    const authHash = await bcrypt.hash(authKey, 12);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userRes = await client.query(
        `INSERT INTO users (email, salt, auth_hash, last_login_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id, email, created_at`,
        [email, salt, authHash]
      );

      const newUser = userRes.rows[0];

      await client.query(
        `INSERT INTO vaults (user_id, ciphertext, iv, version)
         VALUES ($1, '', '', 0)`,
        [newUser.id]
      );

      await client.query('COMMIT');

      await logAuditEvent({
        userId: newUser.id,
        eventType: 'USER_REGISTERED',
        req,
      });

      const token = jwt.sign(
        { userId: newUser.id, email: newUser.email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.status(201).json({
        message: 'Account successfully registered.',
        token,
        user: { id: newUser.id, email: newUser.email },
      });
    } catch (dbErr) {
      await client.query('ROLLBACK');
      throw dbErr;
    } finally {
      client.release();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database error';
    res.status(500).json({ error: 'Failed to complete registration.', details: msg });
  }
});

/**
 * POST /api/auth/login
 * Features:
 * - Brute-force account lockout defense (5 failed attempts locks for 15 minutes)
 * - Timing attack defense on unknown emails
 * - Step-up TOTP verification
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const parseResult = LoginRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { email, authKey } = parseResult.data;

  try {
    const result = await pool.query(
      `SELECT id, email, auth_hash, totp_enabled, failed_login_attempts, locked_until
       FROM users WHERE LOWER(email) = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      await bcrypt.compare(authKey, DUMMY_BCRYPT_HASH);
      res.status(401).json({ error: 'Invalid email or master password.' });
      return;
    }

    const user = result.rows[0];

    // Check account lockout status
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const waitMinutes = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
      res.status(429).json({
        error: `Account temporarily locked due to multiple failed attempts. Try again in ${waitMinutes} minute(s).`,
      });
      return;
    }

    const isMatch = await bcrypt.compare(authKey, user.auth_hash);

    if (!isMatch) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUpdate = '';
      if (newAttempts >= 5) {
        lockUpdate = `, locked_until = NOW() + INTERVAL '15 minutes'`;
      }

      await pool.query(
        `UPDATE users
         SET failed_login_attempts = $1 ${lockUpdate}
         WHERE id = $2`,
        [newAttempts, user.id]
      );

      await logAuditEvent({
        userId: user.id,
        eventType: 'LOGIN_FAILED',
        req,
        details: { attemptNumber: newAttempts },
      });

      res.status(401).json({ error: 'Invalid email or master password.' });
      return;
    }

    // Reset failed attempts on success & update last_login_at
    await pool.query(
      `UPDATE users
       SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW()
       WHERE id = $1`,
      [user.id]
    );

    // Step-up 2FA check
    if (user.totp_enabled) {
      const preAuthToken = jwt.sign(
        { userId: user.id, email: user.email, scope: 'pre-auth' },
        JWT_SECRET,
        { expiresIn: '5m' }
      );

      await logAuditEvent({
        userId: user.id,
        eventType: 'LOGIN_2FA_REQUIRED',
        req,
      });

      res.status(200).json({
        require2fa: true,
        preAuthToken,
      });
      return;
    }

    await logAuditEvent({
      userId: user.id,
      eventType: 'LOGIN_SUCCESS',
      req,
    });

    // Standard Login: Issue full JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Login error';
    res.status(500).json({ error: 'Login failed.', details: msg });
  }
});

/**
 * GET /api/auth/audit
 * Returns recent security events for the authenticated user
 */
authRouter.get('/audit', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  try {
    const result = await pool.query(
      `SELECT event_type, ip_address, user_agent, details, created_at
       FROM audit_logs
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 20`,
      [userId]
    );
    res.status(200).json({ logs: result.rows });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database error';
    res.status(500).json({ error: 'Failed to retrieve audit logs.', details: msg });
  }
});
