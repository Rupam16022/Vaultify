import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from '../db/pool';
import { SaltRequestSchema, RegisterRequestSchema, LoginRequestSchema } from '../schemas/auth';
import { authRateLimiter } from '../middleware/rateLimiter';

export const authRouter = Router();

// Apply auth rate limiter to all authentication routes
authRouter.use(authRateLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_development_secret_not_for_prod';
const SALT_PEPPER = process.env.SALT_PEPPER || 'vaultify_deterministic_salt_pepper_secret_2026';

// Dummy bcrypt hash for constant-time comparison on unknown email
const DUMMY_BCRYPT_HASH = '$2a$12$e80yqX4j2b2c4K3vL2r5uOx3b9sLz8sUjL8eY0oJk6iL7vM9m8cOq';

/**
 * POST /api/auth/salt
 *
 * Prevents User Enumeration Attacks:
 * If the user exists, returns their stored salt.
 * If the user does not exist, returns a deterministic pseudo-salt generated
 * by HMAC-SHA256(email, SALT_PEPPER). The fake salt is consistent across
 * requests for the same email and indistinguishable from real salts.
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
 *
 * Zero-Knowledge Registration:
 * Receives: { email, salt, authKey }
 * The master password is never sent. Only the HKDF-derived Auth Key is sent.
 * The server hashes the Auth Key with bcrypt (work factor 12) before storage.
 */
authRouter.post('/register', async (req: Request, res: Response) => {
  const parseResult = RegisterRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { email, salt, authKey } = parseResult.data;

  try {
    // Check if user already exists
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email]);
    if (existing.rows.length > 0) {
      res.status(409).json({ error: 'An account with this email address already exists.' });
      return;
    }

    // Hash the authKey using bcrypt with cost factor 12
    const authHash = await bcrypt.hash(authKey, 12);

    // Insert user & initialize empty vault in a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userRes = await client.query(
        `INSERT INTO users (email, salt, auth_hash)
         VALUES ($1, $2, $3)
         RETURNING id, email, created_at`,
        [email, salt, authHash]
      );

      const newUser = userRes.rows[0];

      // Initialize empty vault record
      await client.query(
        `INSERT INTO vaults (user_id, ciphertext, iv, version)
         VALUES ($1, '', '', 0)`,
        [newUser.id]
      );

      await client.query('COMMIT');

      // Issue JWT token (24 hours)
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
 *
 * Verifies Auth Key against stored bcrypt hash.
 * If TOTP 2FA is active, returns a short-lived `preAuthToken`.
 * Full JWT is only issued when 2FA is completed or if 2FA is disabled.
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
      `SELECT id, email, auth_hash, totp_enabled
       FROM users WHERE LOWER(email) = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      // Execute dummy bcrypt check to equalize response time and prevent timing analysis
      await bcrypt.compare(authKey, DUMMY_BCRYPT_HASH);
      res.status(401).json({ error: 'Invalid email or master password.' });
      return;
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(authKey, user.auth_hash);

    if (!isMatch) {
      res.status(401).json({ error: 'Invalid email or master password.' });
      return;
    }

    // Step-up 2FA check
    if (user.totp_enabled) {
      const preAuthToken = jwt.sign(
        { userId: user.id, email: user.email, scope: 'pre-auth' },
        JWT_SECRET,
        { expiresIn: '5m' }
      );

      res.status(200).json({
        require2fa: true,
        preAuthToken,
      });
      return;
    }

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
