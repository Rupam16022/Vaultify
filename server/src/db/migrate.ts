import { pool } from './pool';

export async function runMigrations() {
  console.log('[Database] Starting database schema migrations...');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Enable pgcrypto for UUID generation if needed
    await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // 2. Create users table
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

    // Ensure new columns exist on users table
    await client.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS backup_codes TEXT[] DEFAULT '{}',
      ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0,
      ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE DEFAULT NULL;
    `);

    // Index on email for fast lookups
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
    `);

    // 3. Create vaults table
    await client.query(`
      CREATE TABLE IF NOT EXISTS vaults (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        version INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    // 4. Create vault_revisions table (Version History Feature)
    await client.query(`
      CREATE TABLE IF NOT EXISTS vault_revisions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        version INT NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_vault_revisions_user_ver
      ON vault_revisions(user_id, version DESC);
    `);

    // 5. Create audit_logs table (Security & Audit Feature)
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        ip_address TEXT DEFAULT NULL,
        user_agent TEXT DEFAULT NULL,
        details JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time
      ON audit_logs(user_id, created_at DESC);
    `);

    await client.query('COMMIT');
    console.log('[Database] All migrations applied successfully with new features (revisions, audit logs, backup codes).');
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
