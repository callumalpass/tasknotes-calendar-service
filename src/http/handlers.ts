import { OAuthTransactionError, type OAuthTransactions } from "../auth/oauth-transactions";
import type { ProviderCallbackQuery, TransactionStartRequest } from "../contracts/transactions";
import { decryptTokenEnvelope } from "../crypto/token-envelope";
import type { Env } from "../env";
import { revokeGoogleTokenBestEffort } from "../provider/google";
import type { TokenEnvelopeRow } from "../storage/token-envelope-row";
import { tokenEnvelopeFromRow } from "../storage/token-envelope-row";
import type { RouteHandlers, RouteInput } from "./router";
import { ContractError } from "./responses";
import { runtimeConfiguration, type RuntimeConfiguration } from "../runtime/configuration";

interface ConnectionRow extends TokenEnvelopeRow {
  id: string;
  principal_id: string;
  status: "active" | "reconnect_required";
  generation: number;
  token_version: number;
  created_at: number;
  updated_at: number;
}

interface PublicConnectionRow {
  id: string;
  status: "active" | "reconnect_required";
  created_at: number;
  updated_at: number;
}

interface IdentityRow {
  id: string;
  provider: string;
  issuer: string;
  subject: string;
}

function authenticated(input: RouteInput): NonNullable<RouteInput["authenticated"]> {
  if (input.authenticated === undefined) throw new Error("authenticated route context is absent");
  return input.authenticated;
}

function body(input: RouteInput): unknown {
  return input.body;
}

function iso(epochSeconds: number): string {
  if (!Number.isSafeInteger(epochSeconds) || epochSeconds < 0) throw new Error("invalid timestamp");
  return new Date(epochSeconds * 1_000).toISOString();
}

async function oauth(
  operation: (transactions: OAuthTransactions) => Promise<unknown>,
  configured: Promise<RuntimeConfiguration>,
): Promise<unknown> {
  try {
    return await operation((await configured).oauthTransactions);
  } catch (error) {
    if (error instanceof OAuthTransactionError) {
      if (error.code === "invalid_request") throw new ContractError("invalid_request");
      if (error.code === "not_found") throw new ContractError("resource_not_found");
      if (error.code === "conflict") throw new ContractError("conflict");
    }
    throw error;
  }
}

export function createHandlers(env: Env): RouteHandlers {
  const configured = runtimeConfiguration(env);
  return {
    healthLive: () => Promise.resolve({ status: "ok" }),
    healthReady: async () => {
      try {
        await configured;
        await env.DB.prepare("SELECT 1 AS ready").first();
        return { status: "ready" };
      } catch {
        throw new ContractError("dependency_unavailable");
      }
    },
    signInStart: (input) =>
      oauth(
        (transactions) => transactions.startSignIn(body(input) as TransactionStartRequest),
        configured,
      ),
    signInStatus: (input) => {
      const request = body(input) as { polling_secret: string };
      return oauth(
        (transactions) =>
          transactions.statusSignIn(input.params["transaction_id"] ?? "", request.polling_secret),
        configured,
      );
    },
    signInRedeem: (input) => {
      const request = body(input) as { polling_secret: string; code_verifier: string };
      return oauth(
        (transactions) =>
          transactions.redeemSignIn(
            input.params["transaction_id"] ?? "",
            request.polling_secret,
            request.code_verifier,
          ),
        configured,
      );
    },
    connectStart: (input) =>
      oauth(
        (transactions) =>
          transactions.startConnect(
            authenticated(input).principalId,
            body(input) as TransactionStartRequest,
          ),
        configured,
      ),
    connectStatus: (input) => {
      const request = body(input) as { polling_secret: string };
      return oauth(
        (transactions) =>
          transactions.statusConnect(
            authenticated(input).principalId,
            input.params["transaction_id"] ?? "",
            request.polling_secret,
          ),
        configured,
      );
    },
    connectRedeem: (input) => {
      const request = body(input) as { polling_secret: string; code_verifier: string };
      return oauth(
        (transactions) =>
          transactions.redeemConnect(
            authenticated(input).principalId,
            input.params["transaction_id"] ?? "",
            request.polling_secret,
            request.code_verifier,
          ),
        configured,
      );
    },
    providerCallback: (input) =>
      oauth(
        (transactions) => transactions.callback(input.query as ProviderCallbackQuery),
        configured,
      ),
    session: (input) => {
      const context = authenticated(input);
      return Promise.resolve({
        principal_id: context.principalId,
        session_id: context.session.id,
        client_kind: context.session.clientKind,
        device_name: context.session.deviceName,
        created_at: context.session.createdAt,
        idle_expires_at: context.session.idleExpiresAt,
        absolute_expires_at: context.session.absoluteExpiresAt,
      });
    },
    connections: async (input) => {
      await configured;
      const rows = await env.DB.prepare(
        `SELECT id, status, created_at, updated_at FROM connections
         WHERE principal_id = ? AND provider = 'google' ORDER BY created_at, id LIMIT 1`,
      )
        .bind(authenticated(input).principalId)
        .all<PublicConnectionRow>();
      return {
        connections: rows.results.map((row) => ({
          id: row.id,
          provider: "google" as const,
          status: row.status,
          created_at: iso(row.created_at),
          updated_at: iso(row.updated_at),
        })),
      };
    },
    disconnect: async (input) => {
      const runtime = await configured;
      const principalId = authenticated(input).principalId;
      const connectionId = input.params["connection_id"] ?? "";
      const row = await env.DB.prepare(
        `SELECT id, principal_id, status, generation, token_version, created_at, updated_at,
                envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext
         FROM connections WHERE id = ? AND principal_id = ? AND provider = 'google' LIMIT 1`,
      )
        .bind(connectionId, principalId)
        .first<ConnectionRow>();
      if (row === null) throw new ContractError("resource_not_found");
      const token = await decryptTokenEnvelope(
        tokenEnvelopeFromRow(row),
        {
          environment: runtime.environment,
          provider: "google",
          principalId,
          connectionId: row.id,
          connectionGeneration: row.generation,
          tokenVersion: row.token_version,
          tokenKind: "calendar_oauth",
        },
        runtime.tokenKeyring,
      );
      const deleted = await env.DB.prepare(
        `DELETE FROM connections WHERE id = ? AND principal_id = ? AND provider = 'google'
         AND generation = ? AND token_version = ? RETURNING id`,
      )
        .bind(row.id, principalId, row.generation, row.token_version)
        .first<{ id: string }>();
      if (deleted?.id !== row.id) throw new ContractError("conflict");
      try {
        await revokeGoogleTokenBestEffort({
          configuration: runtime.googleProvider,
          token: token.refreshToken,
          fetch: runtime.outboundFetch,
          timeoutMs: 5_000,
        });
      } catch {
        // Local deletion and its generation fence are authoritative; provider revocation is best effort.
      }
      return undefined;
    },
    calendars: async () => {
      await configured;
      throw new ContractError("dependency_unavailable");
    },
    events: async () => {
      await configured;
      throw new ContractError("dependency_unavailable");
    },
    devices: async (input) => {
      const runtime = await configured;
      const context = authenticated(input);
      const sessions = await runtime.deviceSessions.list(context.principalId);
      return {
        devices: sessions.map((session) => ({
          id: session.id,
          client_kind: session.clientKind,
          device_name: session.deviceName,
          created_at: session.createdAt,
          last_used_at: session.lastUsedAt,
          current: session.id === context.sessionId,
        })),
      };
    },
    revokeDevice: async (input) => {
      const runtime = await configured;
      const revoked = await runtime.deviceSessions.revoke(
        authenticated(input).principalId,
        input.params["device_id"] ?? "",
      );
      if (!revoked) throw new ContractError("resource_not_found");
      return undefined;
    },
    deleteAccount: async (input) => {
      const runtime = await configured;
      const principalId = authenticated(input).principalId;
      const connection = await env.DB.prepare(
        `SELECT id, principal_id, status, generation, token_version, created_at, updated_at,
                envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext
         FROM connections WHERE principal_id = ? AND provider = 'google' LIMIT 1`,
      )
        .bind(principalId)
        .first<ConnectionRow>();
      let refreshToken: string | undefined;
      if (connection !== null) {
        try {
          refreshToken = (
            await decryptTokenEnvelope(
              tokenEnvelopeFromRow(connection),
              {
                environment: runtime.environment,
                provider: "google",
                principalId,
                connectionId: connection.id,
                connectionGeneration: connection.generation,
                tokenVersion: connection.token_version,
                tokenKind: "calendar_oauth",
              },
              runtime.tokenKeyring,
            )
          ).refreshToken;
        } catch {
          // Local account deletion must still complete when provider token material is corrupt.
        }
      }
      const identity = await env.DB.prepare(
        `SELECT id, provider, issuer, subject FROM external_identities
         WHERE principal_id = ? AND provider = 'google' AND issuer = 'https://accounts.google.com'
         LIMIT 1`,
      )
        .bind(principalId)
        .first<IdentityRow>();
      if (identity === null) throw new ContractError("resource_not_found");
      const result = await runtime.identityDeletion.deletePrincipal({
        authenticatedPrincipalId: principalId,
        identityId: identity.id,
        identity: {
          provider: identity.provider,
          issuer: identity.issuer,
          subject: identity.subject,
        },
      });
      if (result !== "completed") throw new ContractError("resource_not_found");
      if (refreshToken !== undefined) {
        try {
          await revokeGoogleTokenBestEffort({
            configuration: runtime.googleProvider,
            token: refreshToken,
            fetch: runtime.outboundFetch,
            timeoutMs: 5_000,
          });
        } catch {
          // The deletion fence and local cascade are authoritative; revocation is best effort.
        }
      }
      return undefined;
    },
  };
}
