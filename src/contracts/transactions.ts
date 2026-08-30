import { z } from "zod";

import {
  ClientKindSchema,
  DeviceNameSchema,
  OpaqueSecretSchema,
  Rfc3339InstantSchema,
  UrlSchema,
  UuidSchema,
} from "./common";

export const PkceChallengeSchema = z.string().regex(/^[A-Za-z0-9_-]{43,128}$/);
export const PkceVerifierSchema = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);

export const TransactionStartRequestSchema = z.strictObject({
  client_kind: ClientKindSchema,
  device_name: DeviceNameSchema,
  code_challenge: PkceChallengeSchema,
});

export const TransactionStartResponseSchema = z.strictObject({
  transaction_id: UuidSchema,
  authorization_url: UrlSchema,
  polling_secret: OpaqueSecretSchema,
  expires_at: Rfc3339InstantSchema,
});

export const TransactionStatusQuerySchema = z.strictObject({
  polling_secret: OpaqueSecretSchema,
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
  polling_secret: OpaqueSecretSchema,
  code_verifier: PkceVerifierSchema,
});

export const SessionCredentialSchema = z.strictObject({
  credential: OpaqueSecretSchema,
  session_id: UuidSchema,
  idle_expires_at: Rfc3339InstantSchema,
  absolute_expires_at: Rfc3339InstantSchema,
});

export const SignInRedeemResponseSchema = z.strictObject({ session: SessionCredentialSchema });

export const ConnectRedeemResponseSchema = z.strictObject({
  connection_id: UuidSchema,
  status: z.literal("active"),
});

export const ProviderCallbackQuerySchema = z.union([
  z.strictObject({ code: OpaqueSecretSchema, state: OpaqueSecretSchema }),
  z.strictObject({
    error: z.enum(["access_denied", "temporarily_unavailable", "server_error"]),
    state: OpaqueSecretSchema,
  }),
]);

export type TransactionStartRequest = z.infer<typeof TransactionStartRequestSchema>;
export type TransactionStartResponse = z.infer<typeof TransactionStartResponseSchema>;
export type TransactionStatusQuery = z.infer<typeof TransactionStatusQuerySchema>;
export type TransactionStatusResponse = z.infer<typeof TransactionStatusResponseSchema>;
export type TransactionRedeemRequest = z.infer<typeof TransactionRedeemRequestSchema>;
export type SessionCredential = z.infer<typeof SessionCredentialSchema>;
export type SignInRedeemResponse = z.infer<typeof SignInRedeemResponseSchema>;
export type ConnectRedeemResponse = z.infer<typeof ConnectRedeemResponseSchema>;
export type ProviderCallbackQuery = z.infer<typeof ProviderCallbackQuerySchema>;
