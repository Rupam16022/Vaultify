import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn('WARNING: DATABASE_URL environment variable is not defined.');
}

export const pool = new Pool({
  connectionString: connectionString,
  ssl: {
    rejectUnauthorized: false, // Required for Neon cloud connection
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});
