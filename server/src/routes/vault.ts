import { Router, Request, Response } from 'express';
import { pool } from '../db/pool';
import { requireAuth } from '../middleware/auth';
import { SaveVaultSchema } from '../schemas/vault';
import { logAuditEvent } from '../services/auditLogger';

export const vaultRouter = Router();

// Enforce JWT authentication on all vault routes
vaultRouter.use(requireAuth);

/**
 * GET /api/vault
 *
 * Dumb-Server Design:
 * Retrieves the encrypted vault blob for the authenticated user.
 */
vaultRouter.get('/', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  try {
    const result = await pool.query(
      `SELECT ciphertext, iv, version, updated_at
       FROM vaults
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0 || !result.rows[0].ciphertext) {
      res.status(200).json({
        ciphertext: null,
        iv: null,
        version: 0,
        updated_at: null,
      });
      return;
    }

    const row = result.rows[0];

    await logAuditEvent({
      userId,
      eventType: 'VAULT_FETCHED',
      req,
      details: { version: row.version },
    });

    res.status(200).json({
      ciphertext: row.ciphertext,
      iv: row.iv,
      version: row.version,
      updated_at: row.updated_at,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database fetch error';
    res.status(500).json({ error: 'Failed to retrieve vault.', details: msg });
  }
});

/**
 * PUT /api/vault
 *
 * Dumb-Server Design with Revision History:
 * Stores an updated encrypted vault blob with a fresh random 12-byte IV.
 * Automatically archives the previous version in `vault_revisions`.
 */
vaultRouter.put('/', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  const parseResult = SaveVaultSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { ciphertext, iv } = parseResult.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Fetch current vault to archive into vault_revisions
    const currentRes = await client.query(
      `SELECT ciphertext, iv, version FROM vaults WHERE user_id = $1`,
      [userId]
    );

    if (currentRes.rows.length > 0 && currentRes.rows[0].ciphertext) {
      const current = currentRes.rows[0];
      await client.query(
        `INSERT INTO vault_revisions (user_id, version, ciphertext, iv, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [userId, current.version, current.ciphertext, current.iv]
      );
    }

    // 2. Upsert updated vault
    const result = await client.query(
      `INSERT INTO vaults (user_id, ciphertext, iv, version, updated_at)
       VALUES ($1, $2, $3, 1, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET
         ciphertext = EXCLUDED.ciphertext,
         iv = EXCLUDED.iv,
         version = vaults.version + 1,
         updated_at = NOW()
       RETURNING ciphertext, iv, version, updated_at`,
      [userId, ciphertext, iv]
    );

    await client.query('COMMIT');

    const saved = result.rows[0];

    await logAuditEvent({
      userId,
      eventType: 'VAULT_UPDATED',
      req,
      details: { version: saved.version },
    });

    res.status(200).json({
      message: 'Vault securely saved.',
      version: saved.version,
      updated_at: saved.updated_at,
    });
  } catch (err: unknown) {
    await client.query('ROLLBACK');
    const msg = err instanceof Error ? err.message : 'Database update error';
    res.status(500).json({ error: 'Failed to save vault.', details: msg });
  } finally {
    client.release();
  }
});

/**
 * GET /api/vault/revisions
 * Returns list of historical revisions for the authenticated user.
 */
vaultRouter.get('/revisions', async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  try {
    const result = await pool.query(
      `SELECT version, created_at
       FROM vault_revisions
       WHERE user_id = $1
       ORDER BY version DESC
       LIMIT 10`,
      [userId]
    );
    res.status(200).json({ revisions: result.rows });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database error';
    res.status(500).json({ error: 'Failed to load revisions.', details: msg });
  }
});
