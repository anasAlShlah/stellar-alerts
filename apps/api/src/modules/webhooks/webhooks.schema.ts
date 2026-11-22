import { z } from 'zod';
import { cursorSchema, limitSchema } from '../../utils/pagination';

export const maskingRuleSchema = z.object({
  path: z.string().min(1),
  policy: z.enum(['REDACT', 'SHA256_SALTED', 'TRUNCATE', 'OMIT']),
  salt: z.string().optional(),
  truncateOptions: z
    .object({
      prefixLength: z.number().int().nonnegative().optional(),
      suffixLength: z.number().int().nonnegative().optional(),
      separator: z.string().optional(),
    })
    .optional(),
  redactValue: z.string().optional(),
});

export const createWebhookSchema = z.object({
  url: z.string().url().max(2048),
  payloadTemplate: z.string().max(16384).optional(),
  maskingRules: z.array(maskingRuleSchema).optional(),
});

export const webhookParamsSchema = z.object({
  id: z.string().min(1),
});

export const listWebhookLogsQuerySchema = z.object({
  limit: limitSchema,
  cursor: cursorSchema,
});
