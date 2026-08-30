import { z } from "zod";

import { DEVICE_CLIENT_KINDS, isValidDeviceName } from "../domain/device";
import { decodeBase64Url } from "../crypto/base64url";
import { isServiceCredential } from "../domain/service-credential";

export const CLIENT_KINDS = DEVICE_CLIENT_KINDS;
export const MAX_JSON_BODY_BYTES = 16 * 1024;
export const MAX_CURSOR_LENGTH = 2048;
export const MAX_OPAQUE_SECRET_LENGTH = 1024;
export const MAX_RANGE_DAYS = 93;

function canonicalBase64Url(bytes: number): (value: string) => boolean {
  return (value) => {
    try {
      decodeBase64Url(value, { minBytes: bytes, maxBytes: bytes });
      return true;
    } catch {
      return false;
    }
  };
}

export const UuidSchema = z.uuid().refine((value) => value === value.toLowerCase());
export const TransactionIdSchema = z.string().refine(canonicalBase64Url(32));
export const DeviceSessionIdSchema = z.string().refine(canonicalBase64Url(16));
export const PollingSecretSchema = z.string().refine(canonicalBase64Url(32));
export const ServiceCredentialSchema = z.string().refine(isServiceCredential);
export const OAuthStateSchema = z.string().refine(canonicalBase64Url(32));
export const OpaqueSecretSchema = z
  .string()
  .regex(/^[\u0021-\u007e]+$/)
  .min(16)
  .max(MAX_OPAQUE_SECRET_LENGTH);
export const CursorSchema = z.string().min(16).max(MAX_CURSOR_LENGTH);
export const ClientKindSchema = z.enum(CLIENT_KINDS);
export const DeviceNameSchema = z.string().refine(isValidDeviceName);
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
