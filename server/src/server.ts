import { app } from './app';
import { runMigrations } from './db/migrate';

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Run automated schema migrations on startup
    if (process.env.DATABASE_URL) {
      await runMigrations();
    } else {
      console.warn('[Startup] DATABASE_URL not set; skipping automated DB migrations.');
    }

    app.listen(PORT, () => {
      console.log(`[Vaultify Server] Running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
    });
  } catch (error) {
    console.error('[Startup] Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
