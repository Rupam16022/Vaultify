import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthenticatedUser {
  userId: string;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_development_secret_not_for_prod';

/**
 * JWT Authentication Middleware
 * Validates Bearer token in Authorization header.
 * Disallows pre-auth tokens (which are restricted to 2FA verification only).
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Missing or malformed token.' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: string;
      email: string;
      scope?: string;
    };

    if (decoded.scope === 'pre-auth') {
      res.status(403).json({
        error: 'Incomplete authentication. Two-factor authentication required.',
        code: 'TWO_FACTOR_REQUIRED',
      });
      return;
    }

    req.user = {
      userId: decoded.userId,
      email: decoded.email,
    };

    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session token.' });
  }
}
