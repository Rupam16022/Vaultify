import { z } from 'zod';

export const SaltRequestSchema = z.object({
  email: z.string().email('Invalid email address').max(255).transform((val) => val.trim().toLowerCase()),
});

export const RegisterRequestSchema = z.object({
  email: z.string().email('Invalid email address').max(255).transform((val) => val.trim().toLowerCase()),
  salt: z.string().regex(/^[0-9a-f]{32}$/i, 'Salt must be a 32-character hexadecimal string (16 bytes)'),
  authKey: z.string().regex(/^[0-9a-f]{64}$/i, 'Auth key must be a 64-character hexadecimal string (32 bytes)'),
});

export const LoginRequestSchema = z.object({
  email: z.string().email('Invalid email address').max(255).transform((val) => val.trim().toLowerCase()),
  authKey: z.string().regex(/^[0-9a-f]{64}$/i, 'Auth key must be a 64-character hexadecimal string (32 bytes)'),
});
