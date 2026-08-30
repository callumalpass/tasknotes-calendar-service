import type { CreatedDeviceSession, DeviceSessions } from "./device-sessions";
import type { IdentityDeletion } from "./identity-deletion";
import {
  createGoogleCalendarAuthorizationUrl,
  createGoogleSignInAuthorizationUrl,
  GoogleOidcError,
} from "./google-oidc";
import type {
  GoogleCalendarConnectionResult,
  GoogleCalendarTokenExchangeInput,
  GoogleIdentity,
  GoogleOidcClient,
  GoogleOidcEndpoints,
  GoogleTokenExchangeInput,
} from "./google-oidc";
import {
  decryptOAuthTransactionProviderPkce,
  encryptOAuthTransactionProviderPkce,
  oauthTransactionProviderPkceEnvelopeFromRow,
  oauthTransactionProviderPkceEnvelopeToRow,
} from "./oauth-transaction-secrets";
import type { OAuthTransactionProviderPkceRow } from "./oauth-transaction-secrets";
import {
  ProviderCallbackQuerySchema,
  TransactionStartRequestSchema,
} from "../contracts/transactions";
import type {
  ConnectRedeemResponse,
  ProviderCallbackQuery,
  SignInRedeemResponse,
  TransactionStartRequest,
  TransactionStartResponse,
  TransactionStatusResponse,
} from "../contracts/transactions";
import { TransactionIdSchema, UuidSchema } from "../contracts/common";
import { encodeBase64Url } from "../crypto/base64url";
import { sha256 } from "../crypto/digest";
import { createPkceS256Challenge, isValidPkceVerifier } from "../crypto/pkce";
import { randomBytes } from "../crypto/random";
import type { RandomByteSource } from "../crypto/random";
import { encryptTokenEnvelope } from "../crypto/token-envelope";
import type { KeyEncryptionKeyring } from "../crypto/token-envelope";
import { tokenEnvelopeToRow } from "../storage/token-envelope-row";

const TRANSACTION_LIFETIME_SECONDS = 600;
const EXCHANGE_DEADLINE_SECONDS = 30;
const CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";
const CANONICAL_ISSUER = "https://accounts.google.com";
const textEncoder = new TextEncoder();

export type OAuthTransactionErrorCode = "invalid_request" | "not_found" | "conflict" | "internal";

export class OAuthTransactionError extends Error {
  public readonly code: OAuthTransactionErrorCode;

  public constructor(code: OAuthTransactionErrorCode) {
    super("OAuth transaction could not be completed");
    this.name = "OAuthTransactionError";
    this.code = code;
  }
}

export interface GoogleOAuthTransactionsDependency {
  readonly endpoints: GoogleOidcEndpoints;
  readonly client: GoogleOidcClient;
  readonly exchangeSignIn: (input: GoogleTokenExchangeInput) => Promise<GoogleIdentity>;
  readonly exchangeCalendar: (
    input: GoogleCalendarTokenExchangeInput,
  ) => Promise<GoogleCalendarConnectionResult>;
  readonly revokeCalendarToken: (refreshToken: string) => Promise<unknown>;
}

export interface OAuthTransactionsDependencies {
  readonly db: D1Database;
  readonly environment: "local" | "lab" | "staging" | "production";
  readonly nowEpochSeconds: () => number;
  readonly random: RandomByteSource;
  readonly uuid: () => string;
  readonly transactionKeyring: KeyEncryptionKeyring;
  readonly tokenKeyring: KeyEncryptionKeyring;
  readonly identityDeletion: Pick<IdentityDeletion, "fenceDigest">;
  readonly deviceSessions: Pick<DeviceSessions, "redeemSignInTransaction">;
  readonly google: GoogleOAuthTransactionsDependency;
}

export interface OAuthCallbackResult {
  readonly status: "complete";
}

interface PendingRow extends OAuthTransactionProviderPkceRow {
  id: string;
  intent: "sign_in" | "connect_calendar";
  nonce_hash: string;
  expires_at: number;
}

interface ClaimedRow {
  id: string;
  intent: "sign_in" | "connect_calendar";
  nonce_hash: string;
  created_at: number;
  expires_at: number;
  authenticated_principal_id: string | null;
  expected_identity_id: string | null;
  expected_connection_generation: number | null;
  expected_connection_id: string | null;
  expected_token_version: number | null;
  target_connection_id: string | null;
  target_connection_generation: number | null;
  target_token_version: number | null;
  expected_subject: string | null;
}

interface CapabilityRow {
  status: string;
  expires_at: number;
}

interface StatusRow extends CapabilityRow {
  failure_code: string | null;
}

function fail(code: OAuthTransactionErrorCode): never {
  throw new OAuthTransactionError(code);
}

function now(dependencies: OAuthTransactionsDependencies): number {
  const value = dependencies.nowEpochSeconds();
  if (!Number.isSafeInteger(value) || value < 0) return fail("internal");
  return value;
}

function canonicalUuid(value: unknown): string {
  const parsed = UuidSchema.safeParse(value);
  if (!parsed.success) return fail("internal");
  return parsed.data;
}

function validatePrincipal(value: unknown): string {
  const parsed = UuidSchema.safeParse(value);
  if (!parsed.success) return fail("invalid_request");
  return parsed.data;
}

function validateTransactionId(value: unknown): string {
  const parsed = TransactionIdSchema.safeParse(value);
  if (!parsed.success) return fail("invalid_request");
  return parsed.data;
}

function validateStart(value: unknown): TransactionStartRequest {
  const parsed = TransactionStartRequestSchema.safeParse(value);
  if (!parsed.success) return fail("invalid_request");
  return parsed.data;
}

function secret(source: RandomByteSource): string {
  return encodeBase64Url(randomBytes(source, 32));
}

async function digest(value: string): Promise<string> {
  return encodeBase64Url(await sha256(textEncoder.encode(value)));
}

function iso(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) return fail("internal");
  return new Date(value * 1_000).toISOString();
}

function boundedString(value: unknown, maximumBytes: number, required = true): value is string {
  if (value === undefined && !required) return true;
  if (typeof value !== "string" || value.length === 0) return false;
  return textEncoder.encode(value).length <= maximumBytes;
}

function validIdentity(value: unknown): value is GoogleIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const identity = value as Record<string, unknown>;
  const subject = identity["subject"];
  if (
    identity["issuer"] !== CANONICAL_ISSUER ||
    !boundedString(subject, 255) ||
    Array.from(subject).some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code <= 0x1f || code === 0x7f;
    }) ||
    !boundedString(identity["email"], 2_048, false) ||
    !boundedString(identity["name"], 2_048, false) ||
    (identity["emailVerified"] !== undefined && typeof identity["emailVerified"] !== "boolean")
  ) {
    return false;
  }
  return true;
}

function validCalendarResult(
  value: unknown,
  expectedSubject: string,
): value is GoogleCalendarConnectionResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const result = value as Record<string, unknown>;
  if (!validIdentity(result["identity"]) || result["identity"].subject !== expectedSubject)
    return false;
  const token = result["tokenMaterial"];
  if (typeof token !== "object" || token === null || Array.isArray(token)) return false;
  const material = token as Record<string, unknown>;
  if (
    !boundedString(material["accessToken"], 16_384) ||
    !boundedString(material["refreshToken"], 16_384) ||
    !Number.isSafeInteger(material["expiresInSeconds"]) ||
    (material["expiresInSeconds"] as number) < 1 ||
    (material["expiresInSeconds"] as number) > 86_400 ||
    !Array.isArray(material["scopes"]) ||
    material["scopes"].length === 0 ||
    new Set(material["scopes"]).size !== material["scopes"].length
  ) {
    return false;
  }
  const aliases = new Map([
    ["openid", "openid"],
    ["email", "email"],
    ["https://www.googleapis.com/auth/userinfo.email", "email"],
    ["profile", "profile"],
    ["https://www.googleapis.com/auth/userinfo.profile", "profile"],
    [CALENDAR_SCOPE, CALENDAR_SCOPE],
  ]);
  const effective = new Set<string>();
  for (const scope of material["scopes"]) {
    if (typeof scope !== "string" || textEncoder.encode(scope).length > 256) return false;
    const canonical = aliases.get(scope);
    if (canonical === undefined) return false;
    effective.add(canonical);
  }
  return ["openid", "email", "profile", CALENDAR_SCOPE].every((scope) => effective.has(scope));
}

function envelopeBindings(row: OAuthTransactionProviderPkceRow): unknown[] {
  return [
    row.provider_pkce_schema_version,
    row.provider_pkce_key_version,
    row.provider_pkce_dek_iv,
    row.provider_pkce_wrapped_dek,
    row.provider_pkce_payload_iv,
    row.provider_pkce_ciphertext,
  ];
}

export class OAuthTransactions {
  readonly #dependencies: OAuthTransactionsDependencies;

  public constructor(dependencies: OAuthTransactionsDependencies) {
    if (!["local", "lab", "staging", "production"].includes(dependencies.environment)) {
      throw new TypeError("OAuth transaction environment is invalid");
    }
    this.#dependencies = dependencies;
  }

  public async startSignIn(request: TransactionStartRequest): Promise<TransactionStartResponse> {
    const input = validateStart(request);
    return this.#start("sign_in", null, input);
  }

  public async startConnect(
    authenticatedPrincipalId: string,
    request: TransactionStartRequest,
  ): Promise<TransactionStartResponse> {
    const principalId = validatePrincipal(authenticatedPrincipalId);
    const input = validateStart(request);
    return this.#start("connect_calendar", principalId, input);
  }

  async #start(
    intent: "sign_in" | "connect_calendar",
    principalId: string | null,
    input: TransactionStartRequest,
  ): Promise<TransactionStartResponse> {
    const createdAt = now(this.#dependencies);
    const expiresAt = createdAt + TRANSACTION_LIFETIME_SECONDS;
    const transactionId = secret(this.#dependencies.random);
    const state = secret(this.#dependencies.random);
    const pollingSecret = secret(this.#dependencies.random);
    const nonce = secret(this.#dependencies.random);
    const providerVerifier = secret(this.#dependencies.random);
    const targetConnectionCandidate =
      intent === "connect_calendar" ? canonicalUuid(this.#dependencies.uuid()) : null;
    const [stateHash, pollingHash, nonceHash, providerChallenge] = await Promise.all([
      digest(state),
      digest(pollingSecret),
      digest(nonce),
      createPkceS256Challenge(providerVerifier),
    ]);
    const envelope = oauthTransactionProviderPkceEnvelopeToRow(
      await encryptOAuthTransactionProviderPkce(
        providerVerifier,
        { environment: this.#dependencies.environment, transactionId, intent },
        this.#dependencies.transactionKeyring,
        this.#dependencies.random,
      ),
    );

    try {
      let result: D1Result;
      if (intent === "sign_in") {
        result = await this.#dependencies.db
          .prepare(
            `INSERT INTO oauth_transactions (
               id, intent, status, state_hash, nonce_hash, polling_secret_hash,
               tasknotes_pkce_challenge, provider_pkce_schema_version,
               provider_pkce_key_version, provider_pkce_dek_iv, provider_pkce_wrapped_dek,
               provider_pkce_payload_iv, provider_pkce_ciphertext, device_name, client_kind,
               created_at, expires_at
             ) VALUES (?, 'sign_in', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            transactionId,
            stateHash,
            nonceHash,
            pollingHash,
            input.code_challenge,
            ...envelopeBindings(envelope),
            input.device_name,
            input.client_kind,
            createdAt,
            expiresAt,
          )
          .run();
      } else {
        result = await this.#dependencies.db
          .prepare(
            `INSERT INTO oauth_transactions (
               id, intent, status, state_hash, nonce_hash, polling_secret_hash,
               tasknotes_pkce_challenge, provider_pkce_schema_version,
               provider_pkce_key_version, provider_pkce_dek_iv, provider_pkce_wrapped_dek,
               provider_pkce_payload_iv, provider_pkce_ciphertext,
               authenticated_principal_id, expected_identity_id,
               expected_connection_generation, expected_connection_id, expected_token_version,
               target_connection_id, target_connection_generation, target_token_version,
               device_name, client_kind, created_at, expires_at
             )
             SELECT ?, 'connect_calendar', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    principal.id, identity_record.id, principal.google_connection_generation,
                    connection_record.id, connection_record.token_version,
                    COALESCE(connection_record.id, ?), principal.google_connection_generation + 1,
                    COALESCE(connection_record.token_version + 1, 1), ?, ?, ?, ?
             FROM principals AS principal
             JOIN external_identities AS identity_record
               ON identity_record.principal_id = principal.id
              AND identity_record.provider = 'google'
              AND identity_record.issuer = 'https://accounts.google.com'
             LEFT JOIN connections AS connection_record
               ON connection_record.principal_id = principal.id
              AND connection_record.identity_id = identity_record.id
              AND connection_record.provider = 'google'
             WHERE principal.id = ?`,
          )
          .bind(
            transactionId,
            stateHash,
            nonceHash,
            pollingHash,
            input.code_challenge,
            ...envelopeBindings(envelope),
            targetConnectionCandidate,
            input.device_name,
            input.client_kind,
            createdAt,
            expiresAt,
            principalId,
          )
          .run();
      }
      if (result.meta.changes !== 1) return fail("not_found");
    } catch (error) {
      if (error instanceof OAuthTransactionError) throw error;
      if (intent === "connect_calendar" && principalId !== null) {
        const active = await this.#dependencies.db
          .prepare(
            `SELECT 1 FROM oauth_transactions
             WHERE authenticated_principal_id = ? AND intent = 'connect_calendar'
               AND status IN ('pending', 'exchanging') LIMIT 1`,
          )
          .bind(principalId)
          .first();
        if (active !== null) return fail("conflict");
        const ownedIdentity = await this.#dependencies.db
          .prepare(
            `SELECT 1 FROM principals AS principal
             JOIN external_identities AS identity_record ON identity_record.principal_id = principal.id
             WHERE principal.id = ? AND identity_record.provider = 'google'
               AND identity_record.issuer = 'https://accounts.google.com' LIMIT 1`,
          )
          .bind(principalId)
          .first();
        if (ownedIdentity === null) return fail("not_found");
      }
      return fail("internal");
    }

    const url =
      intent === "sign_in"
        ? createGoogleSignInAuthorizationUrl(
            this.#dependencies.google.endpoints,
            this.#dependencies.google.client,
            { state, nonce, codeChallenge: providerChallenge },
          )
        : createGoogleCalendarAuthorizationUrl(
            this.#dependencies.google.endpoints,
            this.#dependencies.google.client,
            { state, nonce, codeChallenge: providerChallenge, calendarScopes: [CALENDAR_SCOPE] },
          );
    return {
      transaction_id: transactionId,
      authorization_url: url.href,
      polling_secret: pollingSecret,
      expires_at: iso(expiresAt),
    };
  }

  public statusSignIn(
    transactionId: string,
    pollingSecret: string,
  ): Promise<TransactionStatusResponse> {
    return this.#status(null, "sign_in", transactionId, pollingSecret);
  }

  public statusConnect(
    principalId: string,
    transactionId: string,
    pollingSecret: string,
  ): Promise<TransactionStatusResponse> {
    return this.#status(
      validatePrincipal(principalId),
      "connect_calendar",
      transactionId,
      pollingSecret,
    );
  }

  async #status(
    principalId: string | null,
    intent: "sign_in" | "connect_calendar",
    transactionIdValue: string,
    pollingSecret: string,
  ): Promise<TransactionStatusResponse> {
    const transactionId = validateTransactionId(transactionIdValue);
    if (!/^[A-Za-z0-9_-]{43}$/u.test(pollingSecret)) return fail("invalid_request");
    const pollingHash = await digest(pollingSecret);
    const timestamp = now(this.#dependencies);
    const authority =
      intent === "sign_in"
        ? "authenticated_principal_id IS NULL"
        : "authenticated_principal_id = ?";
    const bindings =
      intent === "sign_in"
        ? [transactionId, pollingHash]
        : [transactionId, pollingHash, principalId];
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions
           SET status = 'expired',
               provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL,
               provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL,
               provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL,
               authorized_principal_id = NULL, authorized_identity_id = NULL,
               authorized_connection_id = NULL, callback_completed_at = NULL
           WHERE id = ? AND polling_secret_hash = ? AND intent = '${intent}' AND ${authority}
             AND ((status IN ('pending', 'authorized') AND expires_at <= ?)
               OR (status = 'exchanging' AND (exchange_deadline_at <= ? OR expires_at <= ?)))`,
        )
        .bind(...bindings, timestamp, timestamp, timestamp)
        .run();
      const row = await this.#dependencies.db
        .prepare(
          `SELECT status, failure_code, expires_at FROM oauth_transactions
           WHERE id = ? AND polling_secret_hash = ? AND intent = '${intent}' AND ${authority}
           LIMIT 1`,
        )
        .bind(...bindings)
        .first<StatusRow>();
      if (row === null) return fail("not_found");
      if (row.status === "pending" || row.status === "exchanging") {
        return { status: "pending", expires_at: iso(row.expires_at) };
      }
      if (row.status === "authorized")
        return { status: "authorized", expires_at: iso(row.expires_at) };
      if (row.status === "expired") return { status: "expired" };
      if (
        row.status === "failed" &&
        (row.failure_code === "access_denied" ||
          row.failure_code === "identity_mismatch" ||
          row.failure_code === "authorization_failed")
      ) {
        return { status: "failed", failure_code: row.failure_code };
      }
      if (row.status === "consumed") return fail("conflict");
      return fail("internal");
    } catch (error) {
      if (error instanceof OAuthTransactionError) throw error;
      return fail("internal");
    }
  }

  public async callback(query: ProviderCallbackQuery): Promise<OAuthCallbackResult> {
    const parsed = ProviderCallbackQuerySchema.safeParse(query);
    if (!parsed.success) return fail("invalid_request");
    const stateHash = await digest(parsed.data.state);
    const timestamp = now(this.#dependencies);
    if ("error" in parsed.data) {
      try {
        await this.#dependencies.db
          .prepare(
            `UPDATE oauth_transactions
             SET status = 'failed', failure_code = ?, callback_completed_at = ?,
                 provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL,
                 provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL,
                 provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL
             WHERE state_hash = ? AND status = 'pending'`,
          )
          .bind(
            parsed.data.error === "access_denied" ? "access_denied" : "authorization_failed",
            timestamp,
            stateHash,
          )
          .run();
      } catch {
        // The callback surface is deliberately quiet even for corrupt or concurrently removed rows.
      }
      return { status: "complete" };
    }

    let pending: PendingRow | null;
    try {
      pending = await this.#dependencies.db
        .prepare(
          `SELECT id, intent, nonce_hash, expires_at,
                  provider_pkce_schema_version, provider_pkce_key_version,
                  provider_pkce_dek_iv, provider_pkce_wrapped_dek,
                  provider_pkce_payload_iv, provider_pkce_ciphertext
           FROM oauth_transactions WHERE state_hash = ? AND status = 'pending' LIMIT 1`,
        )
        .bind(stateHash)
        .first<PendingRow>();
    } catch {
      return { status: "complete" };
    }
    if (pending === null) return { status: "complete" };

    let verifier: string;
    try {
      verifier = await decryptOAuthTransactionProviderPkce(
        oauthTransactionProviderPkceEnvelopeFromRow(pending),
        {
          environment: this.#dependencies.environment,
          transactionId: pending.id,
          intent: pending.intent,
        },
        this.#dependencies.transactionKeyring,
      );
    } catch {
      await this.#failPending(stateHash, timestamp);
      return { status: "complete" };
    }
    if (timestamp >= pending.expires_at) return { status: "complete" };

    const deadline = Math.min(timestamp + EXCHANGE_DEADLINE_SECONDS, pending.expires_at);
    let claimed: ClaimedRow | null;
    try {
      claimed = await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions
           SET status = 'exchanging', exchange_started_at = ?, exchange_deadline_at = ?,
               provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL,
               provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL,
               provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL
           WHERE state_hash = ? AND id = ? AND status = 'pending' AND expires_at > ?
           RETURNING id, intent, nonce_hash, created_at, expires_at,
                     authenticated_principal_id, expected_identity_id,
                     expected_connection_generation, expected_connection_id,
                     expected_token_version, target_connection_id,
                     target_connection_generation, target_token_version,
                     (SELECT subject FROM external_identities
                       WHERE id = expected_identity_id
                         AND principal_id = authenticated_principal_id) AS expected_subject`,
        )
        .bind(timestamp, deadline, stateHash, pending.id, timestamp)
        .first<ClaimedRow>();
    } catch {
      return { status: "complete" };
    }
    if (claimed === null) return { status: "complete" };

    try {
      if (claimed.intent === "sign_in") {
        const identity = await this.#dependencies.google.exchangeSignIn({
          code: parsed.data.code,
          codeVerifier: verifier,
          expectedNonceHash: claimed.nonce_hash,
        });
        if (!validIdentity(identity)) throw new GoogleOidcError("invalid_id_token");
        await this.#finalizeSignIn(claimed, identity);
      } else {
        if (claimed.expected_subject === null) throw new GoogleOidcError("identity_mismatch");
        const result = await this.#dependencies.google.exchangeCalendar({
          code: parsed.data.code,
          codeVerifier: verifier,
          expectedNonceHash: claimed.nonce_hash,
          expectedSubject: claimed.expected_subject,
          requiredCalendarScopes: [CALENDAR_SCOPE],
        });
        if (!validCalendarResult(result, claimed.expected_subject)) {
          const identity = (result as { identity?: { subject?: unknown } }).identity;
          throw new GoogleOidcError(
            identity?.subject !== undefined && identity.subject !== claimed.expected_subject
              ? "identity_mismatch"
              : "invalid_token_response",
          );
        }
        await this.#finalizeConnect(claimed, result);
      }
    } catch (error) {
      await this.#failClaimed(
        claimed.id,
        error instanceof GoogleOidcError && error.code === "identity_mismatch"
          ? "identity_mismatch"
          : "authorization_failed",
      );
    }
    return { status: "complete" };
  }

  async #failPending(stateHash: string, timestamp: number): Promise<void> {
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions SET status = 'failed', failure_code = 'authorization_failed',
             callback_completed_at = ?, provider_pkce_schema_version = NULL,
             provider_pkce_key_version = NULL, provider_pkce_dek_iv = NULL,
             provider_pkce_wrapped_dek = NULL, provider_pkce_payload_iv = NULL,
             provider_pkce_ciphertext = NULL
           WHERE state_hash = ? AND status = 'pending'`,
        )
        .bind(timestamp, stateHash)
        .run();
    } catch {
      // Nothing sensitive or actionable is exposed at the callback boundary.
    }
  }

  async #failClaimed(
    transactionId: string,
    failureCode: "identity_mismatch" | "authorization_failed",
  ): Promise<void> {
    const timestamp = now(this.#dependencies);
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions SET status = 'failed', failure_code = ?, callback_completed_at = ?
           WHERE id = ? AND status = 'exchanging'`,
        )
        .bind(failureCode, timestamp, transactionId)
        .run();
    } catch {
      // A later status call terminalizes an abandoned exchange at its deadline.
    }
  }

  async #finalizeSignIn(transaction: ClaimedRow, identity: GoogleIdentity): Promise<void> {
    const completedAt = now(this.#dependencies);
    const candidatePrincipalId = canonicalUuid(this.#dependencies.uuid());
    const candidateIdentityId = canonicalUuid(this.#dependencies.uuid());
    const fence = await this.#dependencies.identityDeletion.fenceDigest({
      provider: "google",
      issuer: CANONICAL_ISSUER,
      subject: identity.subject,
    });
    const email = identity.email ?? null;
    const name = identity.name ?? null;
    const verified = identity.emailVerified === true ? 1 : 0;
    try {
      await this.#dependencies.db.batch([
        this.#dependencies.db
          .prepare(
            `INSERT INTO principals (id, created_at, last_active_at)
             SELECT ?, ?, ?
             WHERE EXISTS (SELECT 1 FROM oauth_transactions
               WHERE id = ? AND status = 'exchanging' AND intent = 'sign_in'
                 AND expires_at > ?)
               AND NOT EXISTS (SELECT 1 FROM external_identities
                 WHERE provider = 'google' AND issuer = ? AND subject = ?)
               AND NOT EXISTS (SELECT 1 FROM identity_deletion_fences
                 WHERE identity_digest = ? AND deleted_at >= ?)`,
          )
          .bind(
            candidatePrincipalId,
            transaction.created_at,
            completedAt,
            transaction.id,
            completedAt,
            CANONICAL_ISSUER,
            identity.subject,
            fence,
            transaction.created_at,
          ),
        this.#dependencies.db
          .prepare(
            `INSERT INTO external_identities
               (id, principal_id, provider, issuer, subject, email, display_name,
                email_verified, created_at, updated_at)
             SELECT ?, ?, 'google', ?, ?, ?, ?, ?, ?, ?
             WHERE EXISTS (SELECT 1 FROM oauth_transactions
               WHERE id = ? AND status = 'exchanging' AND intent = 'sign_in'
                 AND expires_at > ?)
               AND NOT EXISTS (SELECT 1 FROM identity_deletion_fences
                 WHERE identity_digest = ? AND deleted_at >= ?)
             ON CONFLICT(provider, issuer, subject) DO UPDATE SET
               email = excluded.email, display_name = excluded.display_name,
               email_verified = excluded.email_verified, updated_at = excluded.updated_at`,
          )
          .bind(
            candidateIdentityId,
            candidatePrincipalId,
            CANONICAL_ISSUER,
            identity.subject,
            email,
            name,
            verified,
            transaction.created_at,
            completedAt,
            transaction.id,
            completedAt,
            fence,
            transaction.created_at,
          ),
        this.#dependencies.db
          .prepare(
            `UPDATE oauth_transactions
             SET status = 'authorized', authorized_principal_id = identity_record.principal_id,
                 authorized_identity_id = identity_record.id, callback_completed_at = ?
             FROM external_identities AS identity_record
             WHERE oauth_transactions.id = ? AND oauth_transactions.status = 'exchanging'
               AND oauth_transactions.intent = 'sign_in' AND oauth_transactions.expires_at > ?
               AND identity_record.provider = 'google' AND identity_record.issuer = ?
               AND identity_record.subject = ?
               AND NOT EXISTS (SELECT 1 FROM identity_deletion_fences
                 WHERE identity_digest = ? AND deleted_at >= oauth_transactions.created_at)`,
          )
          .bind(
            completedAt,
            transaction.id,
            completedAt,
            CANONICAL_ISSUER,
            identity.subject,
            fence,
          ),
        this.#dependencies.db
          .prepare(
            `UPDATE oauth_transactions SET status = 'failed',
               failure_code = 'authorization_failed', callback_completed_at = ?
             WHERE id = ? AND status = 'exchanging'`,
          )
          .bind(completedAt, transaction.id),
        this.#dependencies.db
          .prepare(
            `DELETE FROM principals WHERE id = ?
             AND NOT EXISTS (SELECT 1 FROM external_identities WHERE principal_id = principals.id)`,
          )
          .bind(candidatePrincipalId),
      ]);
    } catch {
      await this.#failClaimed(transaction.id, "authorization_failed");
    }
  }

  async #finalizeConnect(
    transaction: ClaimedRow,
    result: GoogleCalendarConnectionResult,
  ): Promise<void> {
    const completedAt = now(this.#dependencies);
    const principalId = transaction.authenticated_principal_id;
    const identityId = transaction.expected_identity_id;
    const connectionId = transaction.target_connection_id;
    const generation = transaction.target_connection_generation;
    const tokenVersion = transaction.target_token_version;
    if (
      principalId === null ||
      identityId === null ||
      connectionId === null ||
      generation === null ||
      tokenVersion === null ||
      transaction.expected_subject === null
    ) {
      throw new Error("invalid connect snapshot");
    }
    const refreshToken = result.tokenMaterial.refreshToken;
    let committed = false;
    try {
      const fence = await this.#dependencies.identityDeletion.fenceDigest({
        provider: "google",
        issuer: CANONICAL_ISSUER,
        subject: transaction.expected_subject,
      });
      const envelope = tokenEnvelopeToRow(
        await encryptTokenEnvelope(
          {
            accessToken: result.tokenMaterial.accessToken,
            refreshToken,
            expiresAtEpochSeconds: completedAt + result.tokenMaterial.expiresInSeconds,
            scopes: result.tokenMaterial.scopes,
          },
          {
            environment: this.#dependencies.environment,
            provider: "google",
            principalId,
            connectionId,
            connectionGeneration: generation,
            tokenVersion,
            tokenKind: "calendar_oauth",
          },
          this.#dependencies.tokenKeyring,
          this.#dependencies.random,
        ),
      );
      const eligibility = `EXISTS (SELECT 1 FROM oauth_transactions AS transaction_record
        WHERE transaction_record.id = ? AND transaction_record.status = 'exchanging'
          AND transaction_record.intent = 'connect_calendar' AND transaction_record.expires_at > ?
          AND transaction_record.authenticated_principal_id = ?
          AND transaction_record.expected_identity_id = ?
          AND transaction_record.expected_connection_generation = ?
          AND transaction_record.expected_connection_id IS ?
          AND transaction_record.expected_token_version IS ?
          AND transaction_record.target_connection_id = ?
          AND transaction_record.target_connection_generation = ?
          AND transaction_record.target_token_version = ?
          AND NOT EXISTS (SELECT 1 FROM identity_deletion_fences
            WHERE identity_digest = ? AND deleted_at >= transaction_record.created_at))`;
      const common = [
        transaction.id,
        completedAt,
        principalId,
        identityId,
        transaction.expected_connection_generation,
        transaction.expected_connection_id,
        transaction.expected_token_version,
        connectionId,
        generation,
        tokenVersion,
        fence,
      ];
      const write =
        transaction.expected_connection_id === null
          ? this.#dependencies.db
              .prepare(
                `INSERT INTO connections
               (id, principal_id, identity_id, provider, status, generation,
                envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv,
                ciphertext, token_version, created_at, updated_at, last_provider_success_at)
             SELECT ?, ?, ?, 'google', 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
             WHERE ${eligibility}
               AND EXISTS (SELECT 1 FROM principals WHERE id = ? AND google_connection_generation = ?)
               AND NOT EXISTS (SELECT 1 FROM connections WHERE principal_id = ? AND provider = 'google')`,
              )
              .bind(
                connectionId,
                principalId,
                identityId,
                generation,
                envelope.envelope_schema_version,
                envelope.key_version,
                envelope.dek_iv,
                envelope.wrapped_dek,
                envelope.payload_iv,
                envelope.ciphertext,
                tokenVersion,
                completedAt,
                completedAt,
                completedAt,
                ...common,
                principalId,
                transaction.expected_connection_generation,
                principalId,
              )
          : this.#dependencies.db
              .prepare(
                `UPDATE connections SET status = 'active', generation = ?, token_version = ?,
               envelope_schema_version = ?, key_version = ?, dek_iv = ?, wrapped_dek = ?,
               payload_iv = ?, ciphertext = ?, refresh_lease_owner = NULL,
               refresh_lease_until = NULL, refresh_lease_generation = NULL,
               refresh_lease_token_version = NULL, updated_at = ?, last_provider_success_at = ?
             WHERE id = ? AND principal_id = ? AND identity_id = ? AND provider = 'google'
               AND generation = ? AND token_version = ? AND ${eligibility}
               AND EXISTS (SELECT 1 FROM principals WHERE id = ? AND google_connection_generation = ?)`,
              )
              .bind(
                generation,
                tokenVersion,
                envelope.envelope_schema_version,
                envelope.key_version,
                envelope.dek_iv,
                envelope.wrapped_dek,
                envelope.payload_iv,
                envelope.ciphertext,
                completedAt,
                completedAt,
                connectionId,
                principalId,
                identityId,
                transaction.expected_connection_generation,
                transaction.expected_token_version,
                ...common,
                principalId,
                transaction.expected_connection_generation,
              );
      const results = await this.#dependencies.db.batch([
        write,
        this.#dependencies.db
          .prepare(
            `UPDATE oauth_transactions SET status = 'authorized', authorized_principal_id = ?,
             authorized_identity_id = ?, authorized_connection_id = ?, callback_completed_at = ?
           WHERE id = ? AND status = 'exchanging' AND intent = 'connect_calendar'
             AND expires_at > ? AND authenticated_principal_id = ? AND expected_identity_id = ?
             AND target_connection_id = ? AND target_connection_generation = ?
             AND target_token_version = ?
             AND EXISTS (SELECT 1 FROM connections WHERE id = ? AND principal_id = ?
               AND identity_id = ? AND generation = ? AND token_version = ? AND status = 'active')
             AND NOT EXISTS (SELECT 1 FROM identity_deletion_fences
               WHERE identity_digest = ? AND deleted_at >= oauth_transactions.created_at)`,
          )
          .bind(
            principalId,
            identityId,
            connectionId,
            completedAt,
            transaction.id,
            completedAt,
            principalId,
            identityId,
            connectionId,
            generation,
            tokenVersion,
            connectionId,
            principalId,
            identityId,
            generation,
            tokenVersion,
            fence,
          ),
        this.#dependencies.db
          .prepare(
            `UPDATE oauth_transactions SET status = 'failed', failure_code = 'authorization_failed',
             callback_completed_at = ? WHERE id = ? AND status = 'exchanging'`,
          )
          .bind(completedAt, transaction.id),
      ]);
      if (results.length !== 3) throw new Error("connect finalization batch was incomplete");
      const authorized = await this.#dependencies.db
        .prepare(
          `SELECT 1 FROM oauth_transactions AS transaction_record
           JOIN connections AS connection_record
             ON connection_record.id = transaction_record.authorized_connection_id
            AND connection_record.principal_id = transaction_record.authorized_principal_id
           WHERE transaction_record.id = ? AND transaction_record.status = 'authorized'
             AND connection_record.id = ? AND connection_record.generation = ?
             AND connection_record.token_version = ? AND connection_record.status = 'active'`,
        )
        .bind(transaction.id, connectionId, generation, tokenVersion)
        .first();
      committed = authorized !== null;
    } finally {
      if (!committed) {
        try {
          await this.#dependencies.google.revokeCalendarToken(refreshToken);
        } catch {
          /* best effort */
        }
      }
    }
  }

  public async redeemSignIn(
    transactionIdValue: string,
    pollingSecret: string,
    tasknotesVerifier: string,
  ): Promise<SignInRedeemResponse> {
    const transactionId = validateTransactionId(transactionIdValue);
    const { pollingHash, challenge } = await this.#redemptionBindings(
      pollingSecret,
      tasknotesVerifier,
    );
    await this.#assertRedeemable(null, "sign_in", transactionId, pollingHash, challenge);
    const session = await this.#dependencies.deviceSessions.redeemSignInTransaction({
      transactionId,
      expectedPollingDigest: pollingHash,
      expectedTasknotesPkceChallenge: challenge,
    });
    if (session === null) return fail("conflict");
    return { session: this.#sessionCredential(session) };
  }

  public async redeemConnect(
    principalIdValue: string,
    transactionIdValue: string,
    pollingSecret: string,
    tasknotesVerifier: string,
  ): Promise<ConnectRedeemResponse> {
    const principalId = validatePrincipal(principalIdValue);
    const transactionId = validateTransactionId(transactionIdValue);
    const { pollingHash, challenge } = await this.#redemptionBindings(
      pollingSecret,
      tasknotesVerifier,
    );
    await this.#assertRedeemable(
      principalId,
      "connect_calendar",
      transactionId,
      pollingHash,
      challenge,
    );
    const timestamp = now(this.#dependencies);
    try {
      const row = await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions SET status = 'consumed', consumed_at = ?
         WHERE id = ? AND intent = 'connect_calendar' AND status = 'authorized'
           AND authenticated_principal_id = ? AND authorized_principal_id = ?
           AND polling_secret_hash = ? AND tasknotes_pkce_challenge = ? AND expires_at > ?
           AND EXISTS (SELECT 1 FROM connections WHERE id = authorized_connection_id
             AND principal_id = ? AND status = 'active')
         RETURNING authorized_connection_id AS connection_id`,
        )
        .bind(
          timestamp,
          transactionId,
          principalId,
          principalId,
          pollingHash,
          challenge,
          timestamp,
          principalId,
        )
        .first<{ connection_id: string }>();
      if (row === null || !UuidSchema.safeParse(row.connection_id).success) return fail("conflict");
      return { connection_id: row.connection_id, status: "active" };
    } catch (error) {
      if (error instanceof OAuthTransactionError) throw error;
      return fail("internal");
    }
  }

  async #redemptionBindings(
    pollingSecret: string,
    verifier: string,
  ): Promise<{ pollingHash: string; challenge: string }> {
    if (!/^[A-Za-z0-9_-]{43}$/u.test(pollingSecret) || !isValidPkceVerifier(verifier))
      return fail("invalid_request");
    return {
      pollingHash: await digest(pollingSecret),
      challenge: await createPkceS256Challenge(verifier),
    };
  }

  async #assertRedeemable(
    principalId: string | null,
    intent: "sign_in" | "connect_calendar",
    transactionId: string,
    pollingHash: string,
    challenge: string,
  ): Promise<void> {
    const timestamp = now(this.#dependencies);
    const principalSql =
      intent === "sign_in"
        ? "authenticated_principal_id IS NULL"
        : "authenticated_principal_id = ?";
    const values =
      intent === "sign_in"
        ? [transactionId, pollingHash, challenge]
        : [transactionId, pollingHash, challenge, principalId];
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE oauth_transactions SET status = 'expired', authorized_principal_id = NULL,
           authorized_identity_id = NULL, authorized_connection_id = NULL, callback_completed_at = NULL
         WHERE id = ? AND polling_secret_hash = ? AND tasknotes_pkce_challenge = ?
           AND intent = '${intent}' AND ${principalSql} AND status = 'authorized' AND expires_at <= ?`,
        )
        .bind(...values, timestamp)
        .run();
      const row = await this.#dependencies.db
        .prepare(
          `SELECT status, expires_at FROM oauth_transactions WHERE id = ?
           AND polling_secret_hash = ? AND tasknotes_pkce_challenge = ?
           AND intent = '${intent}' AND ${principalSql} LIMIT 1`,
        )
        .bind(...values)
        .first<CapabilityRow>();
      if (row === null) return fail("not_found");
      if (row.status !== "authorized" || row.expires_at <= timestamp) return fail("conflict");
    } catch (error) {
      if (error instanceof OAuthTransactionError) throw error;
      return fail("internal");
    }
  }

  #sessionCredential(session: CreatedDeviceSession): SignInRedeemResponse["session"] {
    return {
      credential: session.credential,
      session_id: session.id,
      idle_expires_at: session.idleExpiresAt,
      absolute_expires_at: session.absoluteExpiresAt,
    };
  }
}
