import { normalizeGoogleScopes } from "../auth/google-scopes";
import { canonicalUuid } from "../contracts/common";
import { encodeBase64Url } from "../crypto/base64url";
import { randomBytes, type RandomByteSource } from "../crypto/random";
import {
  decryptTokenEnvelope,
  encryptTokenEnvelope,
  type KeyEncryptionKeyring,
  type TokenEnvelope,
  type TokenPayload,
} from "../crypto/token-envelope";
import {
  refreshGoogleToken,
  retryAfter,
  type GoogleProviderConfiguration,
} from "../provider/google";
import type { ProviderError } from "../provider/types";
import { tokenEnvelopeFromRow, tokenEnvelopeToRow } from "../storage/token-envelope-row";

const TOKEN_KIND = "calendar_oauth";
const FRESHNESS_SKEW_SECONDS = 60;
const LEASE_SECONDS = 120;
const LOSER_DELAYS_MS = [50, 100, 200, 400, 800] as const;
const RETRY_AFTER_SECONDS = 1;
const ENVIRONMENTS = new Set(["local", "lab", "staging", "production"]);
const textEncoder = new TextEncoder();

export type GoogleAccessTokenErrorCode =
  "reconnect" | "conflict" | "rate_limited" | "unavailable" | "internal";

export class GoogleAccessTokenError extends Error {
  public readonly code: GoogleAccessTokenErrorCode;
  public readonly retryAfterSeconds?: number;

  public constructor(code: GoogleAccessTokenErrorCode, retryAfterSeconds?: number) {
    super("Google access token operation failed.");
    this.name = "GoogleAccessTokenError";
    this.code = code;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
    Object.freeze(this);
  }
}

export interface ConnectionSnapshot {
  readonly principalId: string;
  readonly connectionId: string;
  readonly generation: number;
  readonly tokenVersion: number;
  readonly principalGeneration: number;
}

export interface AccessGrant {
  readonly accessToken: string;
  readonly principalId: string;
  readonly connectionId: string;
  readonly generation: number;
  readonly tokenVersion: number;
  readonly principalGeneration: number;
}

export interface GoogleAccessTokensDependencies {
  readonly db: D1Database;
  readonly environment: "local" | "lab" | "staging" | "production";
  readonly googleClientId: string;
  readonly googleClientSecret: string;
  readonly tokenKeyring: KeyEncryptionKeyring;
  readonly googleProvider: GoogleProviderConfiguration;
  readonly fetch: typeof fetch;
  readonly random: RandomByteSource;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly providerTimeoutMs?: number;
}

interface ConnectionRow {
  readonly id: string;
  readonly principal_id: string;
  readonly status: "active" | "reconnect_required";
  readonly generation: number;
  readonly principal_generation: number;
  readonly token_version: number;
  readonly envelope_schema_version: number;
  readonly key_version: number;
  readonly dek_iv: string;
  readonly wrapped_dek: string;
  readonly payload_iv: string;
  readonly ciphertext: string;
  readonly refresh_lease_owner: string | null;
  readonly refresh_lease_until: number | null;
  readonly refresh_lease_generation: number | null;
  readonly refresh_lease_token_version: number | null;
  readonly updated_at: number;
  readonly database_now: number;
}

interface SnapshotState {
  readonly row: ConnectionRow;
  readonly payload: TokenPayload;
}

function failure(code: GoogleAccessTokenErrorCode, retryAfterSeconds?: number): never {
  throw new GoogleAccessTokenError(code, retryAfterSeconds);
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) return failure("internal");
  return value as number;
}

function epoch(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) return failure("internal");
  return value as number;
}

function boundedSecret(value: unknown): value is string {
  return (
    typeof value === "string" && value.length > 0 && textEncoder.encode(value).length <= 16_384
  );
}

function parseRow(value: unknown): ConnectionRow {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return failure("internal");
  const row = value as Record<string, unknown>;
  const status = row["status"];
  if (
    (status !== "active" && status !== "reconnect_required") ||
    !boundedSecret(row["dek_iv"]) ||
    !boundedSecret(row["wrapped_dek"]) ||
    !boundedSecret(row["payload_iv"]) ||
    !boundedSecret(row["ciphertext"]) ||
    (row["refresh_lease_owner"] !== null && !boundedSecret(row["refresh_lease_owner"])) ||
    (row["refresh_lease_until"] !== null &&
      (!Number.isSafeInteger(row["refresh_lease_until"]) ||
        (row["refresh_lease_until"] as number) < 0)) ||
    (row["refresh_lease_generation"] !== null &&
      (!Number.isSafeInteger(row["refresh_lease_generation"]) ||
        (row["refresh_lease_generation"] as number) < 1)) ||
    (row["refresh_lease_token_version"] !== null &&
      (!Number.isSafeInteger(row["refresh_lease_token_version"]) ||
        (row["refresh_lease_token_version"] as number) < 1))
  ) {
    return failure("internal");
  }
  const leaseNull = row["refresh_lease_owner"] === null;
  if (
    [
      row["refresh_lease_until"],
      row["refresh_lease_generation"],
      row["refresh_lease_token_version"],
    ].some((part) => (part === null) !== leaseNull)
  ) {
    return failure("internal");
  }
  const parsed: ConnectionRow = {
    id: canonicalUuid(row["id"]) ?? failure("internal"),
    principal_id: canonicalUuid(row["principal_id"]) ?? failure("internal"),
    status,
    generation: positiveInteger(row["generation"]),
    principal_generation: positiveInteger(row["principal_generation"]),
    token_version: positiveInteger(row["token_version"]),
    envelope_schema_version: positiveInteger(row["envelope_schema_version"]),
    key_version: positiveInteger(row["key_version"]),
    dek_iv: row["dek_iv"],
    wrapped_dek: row["wrapped_dek"],
    payload_iv: row["payload_iv"],
    ciphertext: row["ciphertext"],
    refresh_lease_owner: row["refresh_lease_owner"],
    refresh_lease_until: row["refresh_lease_until"] as number | null,
    refresh_lease_generation: row["refresh_lease_generation"] as number | null,
    refresh_lease_token_version: row["refresh_lease_token_version"] as number | null,
    updated_at: epoch(row["updated_at"]),
    database_now: epoch(row["database_now"]),
  };
  if (
    parsed.principal_generation !== parsed.generation ||
    (parsed.refresh_lease_owner !== null &&
      (parsed.refresh_lease_generation !== parsed.generation ||
        parsed.refresh_lease_token_version !== parsed.token_version))
  ) {
    return failure("internal");
  }
  return parsed;
}

function envelope(row: ConnectionRow): TokenEnvelope {
  try {
    return tokenEnvelopeFromRow(row);
  } catch {
    return failure("internal");
  }
}

function normalizedScopes(scopes: readonly unknown[]): readonly string[] {
  try {
    return Object.freeze([...normalizeGoogleScopes(scopes)].sort());
  } catch {
    return failure("internal");
  }
}

function returnedScopes(value: string): readonly string[] {
  if (value.length === 0 || textEncoder.encode(value).length > 32_768) return failure("internal");
  const parts = value.split(/\s+/u);
  if (parts.some((part) => part.length === 0) || new Set(parts).size !== parts.length)
    return failure("internal");
  return normalizedScopes(parts);
}

function sameAuthority(left: ConnectionRow, right: ConnectionRow): boolean {
  return (
    left.id === right.id &&
    left.principal_id === right.principal_id &&
    left.generation === right.generation &&
    left.principal_generation === right.principal_generation
  );
}

function sameEnvelope(left: ConnectionRow, value: TokenEnvelope): boolean {
  return (
    left.envelope_schema_version === value.schemaVersion &&
    left.key_version === value.keyVersion &&
    left.dek_iv === value.dekIv &&
    left.wrapped_dek === value.wrappedDek &&
    left.payload_iv === value.payloadIv &&
    left.ciphertext === value.ciphertext
  );
}

export class GoogleAccessTokens {
  readonly #dependencies: GoogleAccessTokensDependencies;
  readonly #snapshots = new WeakMap<ConnectionSnapshot, SnapshotState>();
  readonly #grants = new WeakSet<AccessGrant>();

  public constructor(dependencies: GoogleAccessTokensDependencies) {
    if (
      !ENVIRONMENTS.has(dependencies.environment) ||
      !boundedSecret(dependencies.googleClientId) ||
      !boundedSecret(dependencies.googleClientSecret)
    ) {
      throw new TypeError("Google access token dependencies are invalid");
    }
    this.#dependencies = dependencies;
  }

  public async loadForPrincipal(principalId: string): Promise<ConnectionSnapshot | null> {
    if (canonicalUuid(principalId) === undefined) failure("internal");
    try {
      const value = await this.#dependencies.db
        .prepare(
          `SELECT connection.id, connection.principal_id, connection.status,
                  connection.generation, principal.google_connection_generation AS principal_generation,
                  connection.token_version, connection.envelope_schema_version, connection.key_version,
                  connection.dek_iv, connection.wrapped_dek, connection.payload_iv,
                  connection.ciphertext, connection.refresh_lease_owner,
                  connection.refresh_lease_until, connection.refresh_lease_generation,
                  connection.refresh_lease_token_version, connection.updated_at,
                  unixepoch() AS database_now
           FROM connections AS connection
           JOIN principals AS principal
             ON principal.id = connection.principal_id
            AND principal.google_connection_generation = connection.generation
           WHERE connection.principal_id = ? AND connection.provider = 'google'
             AND connection.status = 'active' LIMIT 1`,
        )
        .bind(principalId)
        .first();
      if (value === null) {
        const current = await this.#current(principalId);
        if (current?.status === "reconnect_required") return failure("reconnect");
        return null;
      }
      const row = parseRow(value);
      const payload = await this.#decrypt(row);
      const snapshot = Object.freeze({
        principalId: row.principal_id,
        connectionId: row.id,
        generation: row.generation,
        tokenVersion: row.token_version,
        principalGeneration: row.principal_generation,
      });
      this.#snapshots.set(snapshot, { row, payload });
      return snapshot;
    } catch (error) {
      if (error instanceof GoogleAccessTokenError) throw error;
      return failure("internal");
    }
  }

  public async access(
    snapshot: ConnectionSnapshot,
    options: { readonly forceRefresh?: boolean } = {},
  ): Promise<AccessGrant> {
    const state = this.#snapshots.get(snapshot);
    if (
      state === undefined ||
      (options.forceRefresh !== undefined && typeof options.forceRefresh !== "boolean")
    )
      return failure("internal");
    try {
      // The snapshot carries the database clock it was read under, a moment ago.
      if (
        !options.forceRefresh &&
        state.payload.expiresAtEpochSeconds > state.row.database_now + FRESHNESS_SKEW_SECONDS
      )
        return this.#grant(state.row, state.payload.accessToken);
      return await this.#refresh(state.row, state.payload);
    } catch (error) {
      if (error instanceof GoogleAccessTokenError) throw error;
      return failure("internal");
    }
  }

  public async assertCurrent(grant: AccessGrant): Promise<void> {
    try {
      if (!this.#grants.has(grant)) return failure("internal");
      if (canonicalUuid(grant.principalId) === undefined) failure("internal");
      if (canonicalUuid(grant.connectionId) === undefined) failure("internal");
      positiveInteger(grant.generation);
      positiveInteger(grant.principalGeneration);
      const exact = await this.#dependencies.db
        .prepare(
          `SELECT 1 AS current FROM connections AS connection
           JOIN principals AS principal ON principal.id = connection.principal_id
             AND principal.google_connection_generation = connection.generation
           WHERE connection.id = ? AND connection.principal_id = ?
             AND connection.provider = 'google' AND connection.status = 'active'
             AND connection.generation = ?
             AND principal.google_connection_generation = ? LIMIT 1`,
        )
        .bind(grant.connectionId, grant.principalId, grant.generation, grant.principalGeneration)
        .first();
      if (exact !== null) return;
      await this.#failForCurrent(grant.principalId);
    } catch (error) {
      if (error instanceof GoogleAccessTokenError) throw error;
      return failure("internal");
    }
  }

  async #decrypt(row: ConnectionRow): Promise<TokenPayload> {
    try {
      const payload = await decryptTokenEnvelope(
        envelope(row),
        {
          environment: this.#dependencies.environment,
          provider: "google",
          principalId: row.principal_id,
          connectionId: row.id,
          connectionGeneration: row.generation,
          tokenVersion: row.token_version,
          tokenKind: TOKEN_KIND,
        },
        this.#dependencies.tokenKeyring,
      );
      if (
        !boundedSecret(payload.accessToken) ||
        !boundedSecret(payload.refreshToken) ||
        !Number.isSafeInteger(payload.expiresAtEpochSeconds) ||
        payload.expiresAtEpochSeconds < 0
      ) {
        return failure("internal");
      }
      normalizedScopes(payload.scopes);
      return Object.freeze({ ...payload, scopes: Object.freeze([...payload.scopes]) });
    } catch (error) {
      if (error instanceof GoogleAccessTokenError) throw error;
      return failure("internal");
    }
  }

  async #databaseNow(): Promise<number> {
    const value = await this.#dependencies.db
      .prepare("SELECT unixepoch() AS database_now")
      .first("database_now");
    return epoch(value);
  }

  #grant(row: ConnectionRow, accessToken: string): AccessGrant {
    const grant = Object.freeze({
      accessToken,
      principalId: row.principal_id,
      connectionId: row.id,
      generation: row.generation,
      tokenVersion: row.token_version,
      principalGeneration: row.principal_generation,
    });
    this.#grants.add(grant);
    return grant;
  }

  async #current(principalId: string): Promise<ConnectionRow | null> {
    const value = await this.#dependencies.db
      .prepare(
        `SELECT connection.id, connection.principal_id, connection.status,
                connection.generation, principal.google_connection_generation AS principal_generation,
                connection.token_version, connection.envelope_schema_version, connection.key_version,
                connection.dek_iv, connection.wrapped_dek, connection.payload_iv,
                connection.ciphertext, connection.refresh_lease_owner,
                connection.refresh_lease_until, connection.refresh_lease_generation,
                connection.refresh_lease_token_version, connection.updated_at,
                unixepoch() AS database_now
         FROM connections AS connection JOIN principals AS principal
           ON principal.id = connection.principal_id
         WHERE connection.principal_id = ? AND connection.provider = 'google' LIMIT 1`,
      )
      .bind(principalId)
      .first();
    return value === null ? null : parseRow(value);
  }

  async #failForCurrent(principalId: string): Promise<never> {
    const row = await this.#current(principalId);
    return failure(row?.status === "reconnect_required" ? "reconnect" : "conflict");
  }

  async #acquire(row: ConnectionRow, owner: string): Promise<boolean> {
    try {
      const acquired = await this.#dependencies.db
        .prepare(
          `UPDATE connections SET refresh_lease_owner = ?,
             refresh_lease_until = unixepoch() + ${LEASE_SECONDS},
             refresh_lease_generation = generation, refresh_lease_token_version = token_version,
             updated_at = unixepoch()
           WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
             AND generation = ? AND token_version = ?
             AND (refresh_lease_owner IS NULL OR refresh_lease_until <= unixepoch())
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)
           RETURNING refresh_lease_owner, refresh_lease_until, unixepoch() AS database_now`,
        )
        .bind(
          owner,
          row.id,
          row.principal_id,
          row.generation,
          row.token_version,
          row.principal_id,
          row.principal_generation,
        )
        .first<{
          refresh_lease_owner: string;
          refresh_lease_until: number;
          database_now: number;
        }>();
      return (
        acquired?.refresh_lease_owner === owner &&
        epoch(acquired.refresh_lease_until) > epoch(acquired.database_now)
      );
    } catch {
      // D1 can report a transport failure after applying a write. Exact, still-live read-back is
      // the only ownership proof accepted before crossing the provider boundary.
      const current = await this.#current(row.principal_id);
      if (
        current !== null &&
        sameAuthority(row, current) &&
        current.status === "active" &&
        current.token_version === row.token_version &&
        current.refresh_lease_owner === owner &&
        (current.refresh_lease_until ?? 0) > current.database_now
      ) {
        return true;
      }
      if (current !== null && sameAuthority(row, current)) return false;
      return this.#failForCurrent(row.principal_id);
    }
  }

  async #refresh(row: ConnectionRow, payload: TokenPayload): Promise<AccessGrant> {
    let owner: string;
    try {
      owner = encodeBase64Url(randomBytes(this.#dependencies.random, 16));
    } catch {
      return failure("internal");
    }
    if (owner === row.refresh_lease_owner) return failure("internal");
    let current = row;
    const ownsLease = await this.#acquire(current, owner);
    if (!ownsLease) {
      for (const delay of LOSER_DELAYS_MS) {
        current =
          (await this.#current(row.principal_id)) ?? (await this.#failForCurrent(row.principal_id));
        if (!sameAuthority(row, current) || current.status !== "active")
          return this.#failForRow(current);
        if (current.token_version > row.token_version) {
          const winner = await this.#decrypt(current);
          return this.#grant(current, winner.accessToken);
        }
        if (current.token_version !== row.token_version) return failure("conflict");
        if (
          (current.refresh_lease_owner === null ||
            (current.refresh_lease_until ?? 0) <= current.database_now) &&
          (await this.#acquire(current, owner))
        ) {
          return this.#refreshAsOwner(current, payload, owner);
        }
        try {
          await this.#dependencies.sleep(delay);
        } catch {
          return failure("internal");
        }
      }
      current =
        (await this.#current(row.principal_id)) ?? (await this.#failForCurrent(row.principal_id));
      if (current.token_version > row.token_version && sameAuthority(row, current)) {
        const winner = await this.#decrypt(current);
        return this.#grant(current, winner.accessToken);
      }
      if (!sameAuthority(row, current) || current.status !== "active")
        return this.#failForRow(current);
      if (
        (current.refresh_lease_owner === null ||
          (current.refresh_lease_until ?? 0) <= current.database_now) &&
        (await this.#acquire(current, owner))
      ) {
        return this.#refreshAsOwner(current, payload, owner);
      }
      return failure("unavailable", RETRY_AFTER_SECONDS);
    }
    return this.#refreshAsOwner(row, payload, owner);
  }

  #failForRow(row: ConnectionRow): never {
    return failure(row.status === "reconnect_required" ? "reconnect" : "conflict");
  }

  async #refreshAsOwner(
    row: ConnectionRow,
    payload: TokenPayload,
    owner: string,
  ): Promise<AccessGrant> {
    let result: Awaited<ReturnType<typeof refreshGoogleToken>>;
    try {
      result = await refreshGoogleToken({
        clientId: this.#dependencies.googleClientId,
        clientSecret: this.#dependencies.googleClientSecret,
        refreshToken: payload.refreshToken,
        configuration: this.#dependencies.googleProvider,
        fetch: this.#dependencies.fetch,
        ...(this.#dependencies.providerTimeoutMs === undefined
          ? {}
          : { timeoutMs: this.#dependencies.providerTimeoutMs }),
      });
    } catch {
      await this.#releaseLease(row, owner);
      return failure("unavailable");
    }
    if (!result.ok) return this.#providerFailure(row, owner, result.error);
    const refreshed = result.value;
    if (
      !boundedSecret(refreshed.accessToken) ||
      !Number.isSafeInteger(refreshed.expiresInSeconds) ||
      refreshed.expiresInSeconds < 1 ||
      refreshed.expiresInSeconds > 86_400 ||
      (refreshed.refreshToken !== undefined && !boundedSecret(refreshed.refreshToken))
    ) {
      await this.#releaseLease(row, owner);
      return failure("unavailable");
    }
    let scopes: readonly string[];
    try {
      scopes =
        refreshed.scope === undefined
          ? normalizedScopes(payload.scopes)
          : returnedScopes(refreshed.scope);
    } catch {
      await this.#releaseLease(row, owner);
      return failure("unavailable");
    }
    const committedAt = await this.#databaseNow();
    const nextPayload: TokenPayload = {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? payload.refreshToken,
      expiresAtEpochSeconds: committedAt + refreshed.expiresInSeconds,
      scopes,
    };
    let generated: TokenEnvelope;
    try {
      generated = await encryptTokenEnvelope(
        nextPayload,
        {
          environment: this.#dependencies.environment,
          provider: "google",
          principalId: row.principal_id,
          connectionId: row.id,
          connectionGeneration: row.generation,
          tokenVersion: row.token_version + 1,
          tokenKind: TOKEN_KIND,
        },
        this.#dependencies.tokenKeyring,
        this.#dependencies.random,
      );
    } catch {
      return failure("internal");
    }
    return this.#commit(row, owner, generated, nextPayload, committedAt);
  }

  async #releaseLease(row: ConnectionRow, owner: string): Promise<void> {
    await this.#dependencies.db
      .prepare(
        `UPDATE connections SET refresh_lease_owner = NULL, refresh_lease_until = NULL,
         refresh_lease_generation = NULL, refresh_lease_token_version = NULL,
         updated_at = unixepoch()
       WHERE id = ? AND principal_id = ? AND status = 'active'
         AND generation = ? AND token_version = ? AND refresh_lease_owner = ?
         AND refresh_lease_generation = ? AND refresh_lease_token_version = ?
         AND EXISTS (SELECT 1 FROM principals WHERE id = ? AND google_connection_generation = ?)`,
      )
      .bind(
        row.id,
        row.principal_id,
        row.generation,
        row.token_version,
        owner,
        row.generation,
        row.token_version,
        row.principal_id,
        row.principal_generation,
      )
      .run();
  }

  async #providerFailure(row: ConnectionRow, owner: string, error: ProviderError): Promise<never> {
    if (error.code === "reauthorization_required") {
      try {
        const result = await this.#dependencies.db
          .prepare(
            `UPDATE connections SET status = 'reconnect_required',
               refresh_lease_owner = NULL, refresh_lease_until = NULL,
               refresh_lease_generation = NULL, refresh_lease_token_version = NULL,
               discovery_lease_owner = NULL, discovery_lease_until = NULL,
               discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
               updated_at = unixepoch()
             WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
               AND generation = ? AND token_version = ? AND refresh_lease_owner = ?
               AND refresh_lease_generation = ? AND refresh_lease_token_version = ?
               AND EXISTS (SELECT 1 FROM principals WHERE id = ?
                 AND google_connection_generation = ?)`,
          )
          .bind(
            row.id,
            row.principal_id,
            row.generation,
            row.token_version,
            owner,
            row.generation,
            row.token_version,
            row.principal_id,
            row.principal_generation,
          )
          .run();
        if (result.meta.changes === 1) return failure("reconnect");
      } catch {
        // Resolve an ambiguous transition without exposing provider details.
      }
      const current = await this.#current(row.principal_id);
      if (current?.status === "reconnect_required" && sameAuthority(row, current))
        return failure("reconnect");
      return failure("conflict");
    }
    await this.#releaseLease(row, owner);
    if (error.code === "rate_limited")
      return failure("rate_limited", retryAfter(error) ?? RETRY_AFTER_SECONDS);
    return failure("unavailable", retryAfter(error));
  }

  async #commit(
    row: ConnectionRow,
    owner: string,
    generated: TokenEnvelope,
    payload: TokenPayload,
    committedAt: number,
  ): Promise<AccessGrant> {
    const persisted = tokenEnvelopeToRow(generated);
    const execute = async (): Promise<D1Result> =>
      this.#dependencies.db
        .prepare(
          `UPDATE connections SET token_version = token_version + 1,
             envelope_schema_version = ?, key_version = ?, dek_iv = ?, wrapped_dek = ?,
             payload_iv = ?, ciphertext = ?, refresh_lease_owner = NULL,
             refresh_lease_until = NULL, refresh_lease_generation = NULL,
             refresh_lease_token_version = NULL, discovery_lease_owner = NULL,
             discovery_lease_until = NULL, discovery_lease_generation = NULL,
             discovery_lease_token_version = NULL, updated_at = ?, last_provider_success_at = ?
           WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
             AND generation = ? AND token_version = ? AND refresh_lease_owner = ?
             AND refresh_lease_generation = ? AND refresh_lease_token_version = ?
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)`,
        )
        .bind(
          persisted.envelope_schema_version,
          persisted.key_version,
          persisted.dek_iv,
          persisted.wrapped_dek,
          persisted.payload_iv,
          persisted.ciphertext,
          committedAt,
          committedAt,
          row.id,
          row.principal_id,
          row.generation,
          row.token_version,
          owner,
          row.generation,
          row.token_version,
          row.principal_id,
          row.principal_generation,
        )
        .run();
    let ambiguous = false;
    try {
      const result = await execute();
      if (result.meta.changes === 1)
        return this.#grant({ ...row, token_version: row.token_version + 1 }, payload.accessToken);
    } catch {
      ambiguous = true;
    }
    let current = await this.#current(row.principal_id);
    if (
      current !== null &&
      sameAuthority(row, current) &&
      current.token_version === row.token_version + 1
    ) {
      if (sameEnvelope(current, generated)) return this.#grant(current, payload.accessToken);
      const winner = await this.#decrypt(current);
      return this.#grant(current, winner.accessToken);
    }
    if (
      ambiguous &&
      current !== null &&
      sameAuthority(row, current) &&
      current.status === "active" &&
      current.token_version === row.token_version &&
      current.refresh_lease_owner === owner &&
      sameEnvelope(current, envelope(row))
    ) {
      try {
        const retry = await execute();
        if (retry.meta.changes === 1)
          return this.#grant({ ...row, token_version: row.token_version + 1 }, payload.accessToken);
      } catch {
        // One local CAS retry only; provider refresh is never repeated.
      }
      current = await this.#current(row.principal_id);
      if (
        current !== null &&
        sameAuthority(row, current) &&
        current.token_version === row.token_version + 1
      ) {
        if (sameEnvelope(current, generated)) return this.#grant(current, payload.accessToken);
        const winner = await this.#decrypt(current);
        return this.#grant(current, winner.accessToken);
      }
    }
    if (current?.status === "reconnect_required" && sameAuthority(row, current))
      return failure("reconnect");
    return failure("conflict");
  }
}
