import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import path from 'path';
import fs from 'fs';
import { pool } from './db/pool';
import { authRouter } from './routes/auth';
import { twoFactorRouter } from './routes/twoFactor';
import { vaultRouter } from './routes/vault';

export const app = express();

// Trust reverse proxy (Render, Cloudflare, etc.) to read x-forwarded-* headers correctly
app.set('trust proxy', 1);

// 1. Force HTTPS in production environments behind a reverse proxy
app.use((req: Request, res: Response, next: NextFunction) => {
  if (
    process.env.NODE_ENV === 'production' &&
    req.headers['x-forwarded-proto'] &&
    req.headers['x-forwarded-proto'] !== 'https'
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// 2. HTTP Security Headers via Helmet (with strict HSTS & CSP)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: [
          "'self'",
          'https://api.pwnedpasswords.com', // Required for k-Anonymity breach checking
        ],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"], // Prevent clickjacking
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: 'deny',
    },
    noSniff: true,
    xssFilter: true,
  })
);

// 3. Strict payload size limit for incoming JSON (mitigates memory exhaustion / DoS)
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 4. Production Health Check endpoint
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    const dbRes = await pool.query('SELECT NOW() as now');
    res.status(200).json({
      status: 'healthy',
      app: 'Vaultify Zero-Knowledge Vault',
      database: 'connected',
      dbTimestamp: dbRes.rows[0].now,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Unknown DB error';
    res.status(503).json({
      status: 'degraded',
      app: 'Vaultify Zero-Knowledge Vault',
      database: 'disconnected',
      error: errorMsg,
      timestamp: new Date().toISOString(),
    });
  }
});

// 5. API Endpoints
app.use('/api/auth/2fa', twoFactorRouter);
app.use('/api/auth', authRouter);
app.use('/api/vault', vaultRouter);

// 6. Static React Assets & SPA Fallback (Single-Origin Zero-CORS Architecture)
const possiblePaths = [
  path.resolve(process.cwd(), 'client/dist'),
  path.resolve(__dirname, '../../client/dist'),
  path.resolve(__dirname, '../client/dist'),
];
const clientDistPath = possiblePaths.find((p) => fs.existsSync(p)) || possiblePaths[0];

app.use(express.static(clientDistPath));

app.get('*', (req: Request, res: Response, next: NextFunction) => {
  // Do not intercept API routes with HTML fallback
  if (req.path.startsWith('/api/')) {
    return next();
  }
  const indexPath = path.join(clientDistPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  // Fallback if client is not yet built
  res.status(200).send(`
    <!DOCTYPE html>
    <html>
      <head><title>Vaultify Zero-Knowledge</title></head>
      <body style="font-family:sans-serif;padding:2rem;text-align:center;">
        <h1>Vaultify API & Zero-Knowledge Engine</h1>
        <p>Backend is healthy. Client is initializing...</p>
        <p><a href="/api/health">Check /api/health</a></p>
      </body>
    </html>
  `);
});
