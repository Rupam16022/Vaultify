import { Router, Request, Response } from 'express';
import { pool } from '../db/pool';
import { requireAuth } from '../middleware/auth';
import { SaveVaultSchema } from '../schemas/vault';

export const vaultRouter = Router();

// Enforce JWT authentication on all vault routes
vaultRouter.use(requireAuth);

/**
 * GET /api/vault
 *
 * Dumb-Server Design:
 * Retrieves the encrypted vault blob for the authenticated user.
 * The server has zero knowledge of the contents, fields, or keys.
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
 * Dumb-Server Design:
 * Stores an updated encrypted vault blob with a fresh random 12-byte IV.
 * Validates payload schema and updates vault version atomically.
 */
vaultRouter.put('/', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  const parseResult = SaveVaultSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { ciphertext, iv } = parseResult.data;

  try {
    const result = await pool.query(
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

    const saved = result.rows[0];
    res.status(200).json({
      message: 'Vault securely saved.',
      version: saved.version,
      updated_at: saved.updated_at,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Database update error';
    res.status(500).json({ error: 'Failed to save vault.', details: msg });
  }
});
