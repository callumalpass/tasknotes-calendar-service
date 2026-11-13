import { IDLE_LIFETIME_SECONDS } from "../auth/device-sessions";
import {
  OAuthTransactionError,
  type OAuthTransactions,
  type SignInRedemption,
} from "../auth/oauth-transactions";
import { LiveGoogleCalendarError } from "../calendar/live-google-calendar";
import type {
  EventsQuery,
  ChangesQuery,
  CreateEventRequest,
  PatchEventRequest,
} from "../contracts";
import {
  WebSignInRedeemResponseSchema,
  type ProviderCallbackQuery,
  type TransactionStartRequest,
} from "../contracts/transactions";
import { decryptTokenEnvelope } from "../crypto/token-envelope";
import type { Env } from "../env";
import { revokeGoogleTokenBestEffort } from "../provider/google";
import type { TokenEnvelopeRow } from "../storage/token-envelope-row";
import { tokenEnvelopeFromRow } from "../storage/token-envelope-row";
import type { RouteHandlers, RouteInput } from "./router";
import { ContractError, jsonResponse, linkingResponse } from "./responses";
import { sessionCookie } from "./session-cookie";
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

async function calendar<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof LiveGoogleCalendarError) {
      if (error.code === "invalid_request") throw new ContractError("invalid_request");
      if (error.code === "permission_denied") throw new ContractError("permission_denied");
      if (error.code === "sync_reset_required") throw new ContractError("sync_reset_required");
      if (error.code === "not_found")
        throw new ContractError("resource_not_found", undefined, error.detail);
      // Only granting access again clears the first; retrying or re-reading clears the second.
      if (error.code === "reconnect")
        throw new ContractError("reconnect_required", undefined, error.detail);
      if (error.code === "conflict") throw new ContractError("conflict", undefined, error.detail);
      if (error.code === "rate")
        throw new ContractError("rate_limited", error.retryAfterSeconds, error.detail);
      if (error.code === "unavailable")
        throw new ContractError("dependency_unavailable", error.retryAfterSeconds, error.detail);
    }
    throw error;
  }
}

async function refreshTokenForRevocation(
  runtime: RuntimeConfiguration,
  row: ConnectionRow | null,
): Promise<string | undefined> {
  if (row === null) return undefined;
  try {
    return (
      await decryptTokenEnvelope(
        tokenEnvelopeFromRow(row),
        {
          environment: runtime.environment,
          provider: "google",
          principalId: row.principal_id,
          connectionId: row.id,
          connectionGeneration: row.generation,
          tokenVersion: row.token_version,
          tokenKind: "calendar_oauth",
        },
        runtime.tokenKeyring,
      )
    ).refreshToken;
  } catch {
    return undefined;
  }
}

export function createHandlers(env: Env): RouteHandlers {
  const configured = () => runtimeConfiguration(env);
  return {
    healthLive: () => Promise.resolve({ status: "ok" }),
    healthReady: async () => {
      try {
        await configured();
        await env.DB.prepare("SELECT 1 AS ready").first();
        return { status: "ready" };
      } catch {
        throw new ContractError("dependency_unavailable");
      }
    },
    signInStart: (input) =>
      oauth(
        (transactions) => transactions.startSignIn(body(input) as TransactionStartRequest),
        configured(),
      ),
    signInStatus: (input) => {
      const request = body(input) as { polling_secret: string };
      return oauth(
        (transactions) =>
          transactions.statusSignIn(input.params["transaction_id"] ?? "", request.polling_secret),
        configured(),
      );
    },
    signInRedeem: async (input) => {
      const request = body(input) as {
        polling_secret: string;
        code_verifier: string;
        confirmation_code: string;
      };
      const { session, clientKind } = (await oauth(
        (transactions) =>
          transactions.redeemSignIn(
            input.params["transaction_id"] ?? "",
            request.polling_secret,
            request.code_verifier,
            request.confirmation_code,
            input.originAllowed,
          ),
        configured(),
      )) as SignInRedemption;
      if (clientKind !== "web") return { session };
      const { credential, ...webSession } = session;
      const response = jsonResponse(WebSignInRedeemResponseSchema.parse({ session: webSession }));
      response.headers.set("set-cookie", sessionCookie(credential, IDLE_LIFETIME_SECONDS));
      return response;
    },
    connectStart: (input) =>
      oauth(
        (transactions) =>
          transactions.startConnect(
            authenticated(input).principalId,
            body(input) as TransactionStartRequest,
          ),
        configured(),
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
        configured(),
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
        configured(),
      );
    },
    providerCallback: (input) =>
      oauth(
        async (transactions) =>
          linkingResponse(await transactions.callback(input.query as ProviderCallbackQuery)),
        configured(),
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
      });
    },
    connections: async (input) => {
      await configured();
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
    disconnect: async (input, _request, ctx) => {
      const runtime = await configured();
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
      const refreshToken = await refreshTokenForRevocation(runtime, row);
      const deleted = await env.DB.prepare(
        `DELETE FROM connections WHERE id = ? AND principal_id = ? AND provider = 'google'
         AND generation = ? RETURNING id`,
      )
        .bind(row.id, principalId, row.generation)
        .first<{ id: string }>();
      if (deleted?.id !== row.id) throw new ContractError("conflict");
      if (refreshToken !== undefined) {
        ctx.waitUntil(
          revokeGoogleTokenBestEffort({
            configuration: runtime.googleProvider,
            token: refreshToken,
            fetch: runtime.outboundFetch,
            timeoutMs: 5_000,
          }).catch(() => undefined),
        );
      }
      return undefined;
    },
    calendars: async (input) => {
      const runtime = await configured();
      const { calendars, discovery } = await calendar(() =>
        runtime.liveGoogleCalendar.listCalendars(authenticated(input).principalId),
      );
      if (discovery !== undefined) {
        input.log.omittedCount = discovery.omittedCount;
        if (discovery.truncated) input.log.detail = "calendar_list_truncated";
      }
      return { calendars };
    },
    events: async (input) => {
      const runtime = await configured();
      const page = await calendar(() =>
        runtime.liveGoogleCalendar.listEvents(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          input.query as EventsQuery,
        ),
      );
      input.log.omittedCount = page.omitted_count;
      return page;
    },
    changes: async (input) => {
      const runtime = await configured();
      const page = await calendar(() =>
        runtime.liveGoogleCalendar.listChanges(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          input.query as ChangesQuery,
        ),
      );
      input.log.omittedCount = page.omitted_count;
      return page;
    },
    createEvent: async (input, request) => {
      const runtime = await configured();
      return calendar(() =>
        runtime.liveGoogleCalendar.event(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          "POST",
          input.params["event_id"],
          input.body as CreateEventRequest | PatchEventRequest | undefined,
          request.headers.get("If-Match") ?? undefined,
        ),
      );
    },
    getEvent: async (input, request) => {
      const runtime = await configured();
      return calendar(() =>
        runtime.liveGoogleCalendar.event(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          "GET",
          input.params["event_id"],
          input.body as CreateEventRequest | PatchEventRequest | undefined,
          request.headers.get("If-Match") ?? undefined,
        ),
      );
    },
    patchEvent: async (input, request) => {
      const runtime = await configured();
      return calendar(() =>
        runtime.liveGoogleCalendar.event(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          "PATCH",
          input.params["event_id"],
          input.body as CreateEventRequest | PatchEventRequest | undefined,
          request.headers.get("If-Match") ?? undefined,
        ),
      );
    },
    deleteEvent: async (input, request) => {
      const runtime = await configured();
      return calendar(() =>
        runtime.liveGoogleCalendar.event(
          authenticated(input).principalId,
          input.params["calendar_id"] ?? "",
          "DELETE",
          input.params["event_id"],
          input.body as CreateEventRequest | PatchEventRequest | undefined,
          request.headers.get("If-Match") ?? undefined,
        ),
      );
    },
    devices: async (input) => {
      const runtime = await configured();
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
      const runtime = await configured();
      const revoked = await runtime.deviceSessions.revoke(
        authenticated(input).principalId,
        input.params["device_id"] ?? "",
      );
      if (!revoked) throw new ContractError("resource_not_found");
      return undefined;
    },
    deleteAccount: async (input, _request, ctx) => {
      const runtime = await configured();
      const principalId = authenticated(input).principalId;
      const connection = await env.DB.prepare(
        `SELECT id, principal_id, status, generation, token_version, created_at, updated_at,
                envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext
         FROM connections WHERE principal_id = ? AND provider = 'google' LIMIT 1`,
      )
        .bind(principalId)
        .first<ConnectionRow>();
      const refreshToken = await refreshTokenForRevocation(runtime, connection);
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
        ctx.waitUntil(
          revokeGoogleTokenBestEffort({
            configuration: runtime.googleProvider,
            token: refreshToken,
            fetch: runtime.outboundFetch,
            timeoutMs: 5_000,
          }).catch(() => undefined),
        );
      }
      return undefined;
    },
  };
}
