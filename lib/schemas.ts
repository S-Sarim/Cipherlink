import { z } from "zod";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export const CreateSecretSchema = z.object({
  ciphertext: z.string().min(1).max(64 * 1024).regex(BASE64URL),
  iv: z.string().min(1).max(64).regex(BASE64URL),
  salt: z
    .string()
    .min(1)
    .max(64)
    .regex(BASE64URL)
    .nullable()
    .optional(),
  hasPassword: z.boolean(),
  expiresInSec: z
    .number()
    .int()
    .min(60)
    .max(60 * 60 * 24 * 7),
  maxViews: z.number().int().min(1).max(20),
});

export type CreateSecretInput = z.infer<typeof CreateSecretSchema>;
