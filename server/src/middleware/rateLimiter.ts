import rateLimit from 'express-rate-limit';

/**
 * Strict rate limiting on authentication routes (/api/auth/*)
 * Mitigates credential stuffing, salt enumeration, and brute-force attacks.
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 30, // Limit each IP to 30 requests per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  message: {
    error: 'Too many authentication attempts. Please try again in 15 minutes.',
    code: 'RATE_LIMIT_EXCEEDED',
  },
});
