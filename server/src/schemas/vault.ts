import { z } from 'zod';

export const SaveVaultSchema = z.object({
  ciphertext: z.string().min(1, 'Ciphertext cannot be empty').max(1024 * 1024, 'Payload exceeds 1MB limit'),
  iv: z.string().regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, 'IV must be a valid Base64 string'),
  version: z.number().int().nonnegative().optional(),
});
