import { Pool } from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

// Look for .env in current working dir, server dir, and root dir
const candidateEnvPaths = [
  path.resolve(process.cwd(), '.env'),
  path.resolve(process.cwd(), 'server/.env'),
  path.resolve(__dirname, '../.env'),
  path.resolve(__dirname, '../../.env'),
];

for (const p of candidateEnvPaths) {
  if (fs.existsSync(p)) {
    dotenv.config({ path: p });
    break;
  }
}

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
