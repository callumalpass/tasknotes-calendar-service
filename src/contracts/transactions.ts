import { z } from "zod";

import {
  ClientKindSchema,
  DeviceNameSchema,
  DeviceSessionIdSchema,
  OAuthStateSchema,
  OpaqueSecretSchema,
  PollingSecretSchema,
  Rfc3339InstantSchema,
  ServiceCredentialSchema,
  TransactionIdSchema,
  UrlSchema,
  UuidSchema,
} from "./common";

export const PkceChallengeSchema = TransactionIdSchema;
export const PkceVerifierSchema = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);

export const TransactionStartRequestSchema = z.strictObject({
  client_kind: ClientKindSchema,
  device_name: DeviceNameSchema,
  code_challenge: PkceChallengeSchema,
});

export const TransactionStartResponseSchema = z.strictObject({
  transaction_id: TransactionIdSchema,
  authorization_url: UrlSchema,
  polling_secret: PollingSecretSchema,
  expires_at: Rfc3339InstantSchema,
});

export const TransactionStatusRequestSchema = z.strictObject({
  polling_secret: PollingSecretSchema,
});

export const TransactionStatusResponseSchema = z.discriminatedUnion("status", [
  z.strictObject({ status: z.literal("pending"), expires_at: Rfc3339InstantSchema }),
  z.strictObject({ status: z.literal("authorized"), expires_at: Rfc3339InstantSchema }),
  z.strictObject({
    status: z.literal("failed"),
    failure_code: z.enum(["access_denied", "identity_mismatch", "authorization_failed"]),
  }),
  z.strictObject({ status: z.literal("expired") }),
]);

export const TransactionRedeemRequestSchema = z.strictObject({
  polling_secret: PollingSecretSchema,
  code_verifier: PkceVerifierSchema,
});

export const SessionCredentialSchema = z.strictObject({
  credential: ServiceCredentialSchema,
  session_id: DeviceSessionIdSchema,
  idle_expires_at: Rfc3339InstantSchema,
  absolute_expires_at: Rfc3339InstantSchema,
});

export const SignInRedeemResponseSchema = z.strictObject({ session: SessionCredentialSchema });

export const ConnectRedeemResponseSchema = z.strictObject({
  connection_id: UuidSchema,
  status: z.literal("active"),
});

const CallbackMetadataSchema = {
  scope: z
    .string()
    .regex(/^[\u0020-\u007e]{1,2048}$/)
    .optional(),
  authuser: z
    .string()
    .regex(/^\d{1,10}$/)
    .optional(),
  prompt: z
    .string()
    .regex(/^[A-Za-z0-9 _-]{1,128}$/)
    .optional(),
  iss: z.enum(["https://accounts.google.com", "accounts.google.com"]).optional(),
} as const;

export const ProviderCallbackQuerySchema = z.union([
  z.strictObject({ code: OpaqueSecretSchema, state: OAuthStateSchema, ...CallbackMetadataSchema }),
  z.strictObject({
    error: z.string().regex(/^[A-Za-z0-9._~-]{1,128}$/),
    state: OAuthStateSchema,
    error_description: z.string().max(1024).optional(),
    error_uri: z.url().max(2048).optional(),
  }),
]);

export type TransactionStartRequest = z.infer<typeof TransactionStartRequestSchema>;
export type TransactionStartResponse = z.infer<typeof TransactionStartResponseSchema>;
export type TransactionStatusRequest = z.infer<typeof TransactionStatusRequestSchema>;
export type TransactionStatusResponse = z.infer<typeof TransactionStatusResponseSchema>;
export type TransactionRedeemRequest = z.infer<typeof TransactionRedeemRequestSchema>;
export type SessionCredential = z.infer<typeof SessionCredentialSchema>;
export type SignInRedeemResponse = z.infer<typeof SignInRedeemResponseSchema>;
export type ConnectRedeemResponse = z.infer<typeof ConnectRedeemResponseSchema>;
export type ProviderCallbackQuery = z.infer<typeof ProviderCallbackQuerySchema>;
