import { z } from "zod";

export const CLIENT_KINDS = ["web", "ios", "android", "obsidian"] as const;
export const MAX_JSON_BODY_BYTES = 16 * 1024;
export const MAX_CURSOR_LENGTH = 2048;
export const MAX_OPAQUE_SECRET_LENGTH = 1024;
export const MAX_RANGE_DAYS = 93;

export const UuidSchema = z.uuid();
export const TransactionIdSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const DeviceSessionIdSchema = z.string().regex(/^[A-Za-z0-9_-]{22}$/);
export const PollingSecretSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const ServiceCredentialSchema = z
  .string()
  .regex(/^v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);
export const OAuthStateSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const OpaqueSecretSchema = z
  .string()
  .regex(/^[\u0021-\u007e]+$/)
  .min(16)
  .max(MAX_OPAQUE_SECRET_LENGTH);
export const CursorSchema = z.string().min(16).max(MAX_CURSOR_LENGTH);
export const ClientKindSchema = z.enum(CLIENT_KINDS);
export const DeviceNameSchema = z.string().trim().min(1).max(80);
export const Rfc3339InstantSchema = z.iso.datetime({ offset: true });
export const DateSchema = z.iso.date();
export const UrlSchema = z.url().max(2048);

export const EmptyObjectSchema = z.strictObject({});

export const ErrorCodeSchema = z.enum([
  "invalid_request",
  "unsupported_media_type",
  "payload_too_large",
  "authentication_required",
  "permission_denied",
  "resource_not_found",
  "conflict",
  "rate_limited",
  "dependency_unavailable",
  "internal_error",
]);

export const ErrorResponseSchema = z.strictObject({
  code: ErrorCodeSchema,
  message: z.string().min(1).max(160),
});

export type ClientKind = z.infer<typeof ClientKindSchema>;
export type ApiError = z.infer<typeof ErrorResponseSchema>;

export function isBoundedEventRange(start: string, end: string): boolean {
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  return endMs > startMs && endMs - startMs <= MAX_RANGE_DAYS * 24 * 60 * 60 * 1000;
}
