import { pool } from './pool';

export async function runMigrations() {
  console.log('[Database] Starting database schema migrations...');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Enable pgcrypto for UUID generation if needed
    await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        auth_hash TEXT NOT NULL,
        totp_secret TEXT DEFAULT NULL,
        totp_iv TEXT DEFAULT NULL,
        totp_enabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    // Index on email for fast lookups
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
    `);

    // Create vaults table
    await client.query(`
      CREATE TABLE IF NOT EXISTS vaults (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        version INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    await client.query('COMMIT');
    console.log('[Database] Migrations applied successfully.');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[Database] Migration failed:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Allow standalone execution
if (require.main === module) {
  runMigrations()
    .then(() => {
      console.log('[Database] Migration script completed.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[Database] Fatal migration error:', err);
      process.exit(1);
    });
}
