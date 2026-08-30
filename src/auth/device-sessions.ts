import { decodeBase64Url, encodeBase64Url } from "../crypto/base64url";
import { constantTimeEqual } from "../crypto/digest";
import { randomBytes } from "../crypto/random";
import type { RandomByteSource } from "../crypto/random";
import { isDeviceClientKind, isValidDeviceName } from "../domain/device";
import type { DeviceClientKind } from "../domain/device";
import { parseServiceCredential } from "../domain/service-credential";

export type { DeviceClientKind } from "../domain/device";

const CREDENTIAL_VERSION = "v1";
const SESSION_ID_BYTES = 16;
const CREDENTIAL_SECRET_BYTES = 32;
const DIGEST_BYTES = 32;
const IDLE_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const ABSOLUTE_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
const LAST_USED_UPDATE_INTERVAL_SECONDS = 60 * 60;
const MAX_PRINCIPAL_ID_BYTES = 256;
const textEncoder = new TextEncoder();

export interface Clock {
  now(): Date;
}

export interface DeviceSessionDependencies {
  readonly db: D1Database;
  readonly pepper: Uint8Array;
  readonly clock: Clock;
  readonly random: RandomByteSource;
}

export interface CreateDeviceSessionInput {
  readonly principalId: string;
  readonly deviceName: string;
  readonly clientKind: DeviceClientKind;
}

export interface RedeemSignInTransactionInput {
  readonly transactionId: string;
  readonly expectedPollingDigest: string;
  readonly expectedTasknotesPkceChallenge: string;
}

export interface DeviceSessionMetadata {
  readonly id: string;
  readonly deviceName: string;
  readonly clientKind: DeviceClientKind;
  readonly createdAt: string;
  readonly lastUsedAt: string;
  readonly idleExpiresAt: string;
  readonly absoluteExpiresAt: string;
  readonly revokedAt: string | null;
}

export interface CreatedDeviceSession extends DeviceSessionMetadata {
  readonly credential: string;
}

export interface AuthenticatedDeviceSession {
  readonly principalId: string;
  readonly session: DeviceSessionMetadata;
}

interface SessionRow {
  id: string;
  principal_id: string;
  credential_hash: string;
  device_name: string;
  client_kind: string;
  created_at: number;
  last_used_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
}

interface GeneratedCredential {
  id: string;
  credential: string;
  digest: string;
}

interface MetadataRow {
  id: string;
  device_name: string;
  client_kind: string;
  created_at: number;
  last_used_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
}

export class DeviceSessionInputError extends Error {
  public constructor() {
    super("device session input is invalid");
    this.name = "DeviceSessionInputError";
  }
}

export class PrincipalUnavailableError extends Error {
  public constructor() {
    super("principal is unavailable");
    this.name = "PrincipalUnavailableError";
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function validatedNow(clock: Clock): number {
  const now = clock.now();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()) || now.getTime() < 0) {
    throw new TypeError("clock returned an invalid date");
  }
  return Math.floor(now.getTime() / 1_000);
}

function toIso(epochSeconds: number): string {
  if (!Number.isSafeInteger(epochSeconds) || epochSeconds < 0) {
    throw new Error("stored device session has an invalid timestamp");
  }
  return new Date(epochSeconds * 1_000).toISOString();
}

function isBoundedIdentifier(value: unknown, maximumBytes: number): value is string {
  if (typeof value !== "string") return false;
  const hasControlCharacter = Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
  return (
    value.length > 0 &&
    value.length <= maximumBytes &&
    textEncoder.encode(value).length <= maximumBytes &&
    !hasControlCharacter
  );
}

function validatePrincipalId(principalId: string): void {
  if (!isBoundedIdentifier(principalId, MAX_PRINCIPAL_ID_BYTES)) {
    throw new DeviceSessionInputError();
  }
}

function validateDevice(
  deviceName: string,
  clientKind: string,
): asserts clientKind is DeviceClientKind {
  if (!isValidDeviceName(deviceName) || !isDeviceClientKind(clientKind)) {
    throw new DeviceSessionInputError();
  }
}

function validatePepper(pepper: Uint8Array): Uint8Array {
  if (pepper.length !== 32) {
    throw new TypeError("session pepper must be exactly 32 bytes");
  }
  return Uint8Array.from(pepper);
}

async function importPepper(pepper: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    asArrayBuffer(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function credentialDigest(
  pepper: Uint8Array,
  sessionId: Uint8Array,
  secret: Uint8Array,
): Promise<Uint8Array> {
  const message = new Uint8Array(1 + sessionId.length + secret.length);
  message[0] = 1;
  message.set(sessionId, 1);
  message.set(secret, 1 + sessionId.length);
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", await importPepper(pepper), asArrayBuffer(message)),
  );
}

async function generateCredential(
  pepper: Uint8Array,
  random: RandomByteSource,
): Promise<GeneratedCredential> {
  const sessionIdBytes = randomBytes(random, SESSION_ID_BYTES);
  const secret = randomBytes(random, CREDENTIAL_SECRET_BYTES);
  const id = encodeBase64Url(sessionIdBytes);
  return {
    id,
    credential: `${CREDENTIAL_VERSION}.${id}.${encodeBase64Url(secret)}`,
    digest: encodeBase64Url(await credentialDigest(pepper, sessionIdBytes, secret)),
  };
}

function metadata(row: MetadataRow | SessionRow): DeviceSessionMetadata {
  if (!isDeviceClientKind(row.client_kind)) {
    throw new Error("stored device session has an invalid client kind");
  }
  return {
    id: row.id,
    deviceName: row.device_name,
    clientKind: row.client_kind,
    createdAt: toIso(row.created_at),
    lastUsedAt: toIso(row.last_used_at),
    idleExpiresAt: toIso(row.idle_expires_at),
    absoluteExpiresAt: toIso(row.absolute_expires_at),
    revokedAt: row.revoked_at === null ? null : toIso(row.revoked_at),
  };
}

export class DeviceSessions {
  readonly #db: D1Database;
  readonly #pepper: Uint8Array;
  readonly #clock: Clock;
  readonly #random: RandomByteSource;

  public constructor(dependencies: DeviceSessionDependencies) {
    this.#db = dependencies.db;
    this.#pepper = validatePepper(dependencies.pepper);
    this.#clock = dependencies.clock;
    this.#random = dependencies.random;
  }

  public async create(input: CreateDeviceSessionInput): Promise<CreatedDeviceSession> {
    validatePrincipalId(input.principalId);
    validateDevice(input.deviceName, input.clientKind);
    const now = validatedNow(this.#clock);
    const generated = await generateCredential(this.#pepper, this.#random);
    const createdAt = now;
    const idleExpiresAt = now + IDLE_LIFETIME_SECONDS;
    const absoluteExpiresAt = now + ABSOLUTE_LIFETIME_SECONDS;

    const result = await this.#db
      .prepare(
        `INSERT INTO device_sessions (
          id, principal_id, credential_hash, device_name, client_kind, created_at,
          last_used_at, idle_expires_at, absolute_expires_at, revoked_at,
          redemption_transaction_id
        )
        SELECT ?, id, ?, ?, ?, ?, ?, ?, ?, NULL, NULL
        FROM principals
        WHERE id = ?`,
      )
      .bind(
        generated.id,
        generated.digest,
        input.deviceName,
        input.clientKind,
        createdAt,
        createdAt,
        idleExpiresAt,
        absoluteExpiresAt,
        input.principalId,
      )
      .run();
    if (result.meta.changes !== 1) {
      throw new PrincipalUnavailableError();
    }

    return {
      id: generated.id,
      credential: generated.credential,
      deviceName: input.deviceName,
      clientKind: input.clientKind,
      createdAt: toIso(createdAt),
      lastUsedAt: toIso(createdAt),
      idleExpiresAt: toIso(idleExpiresAt),
      absoluteExpiresAt: toIso(absoluteExpiresAt),
      revokedAt: null,
    };
  }

  public async redeemSignInTransaction(
    input: RedeemSignInTransactionInput,
  ): Promise<CreatedDeviceSession | null> {
    if (
      !isBoundedIdentifier(input.transactionId, 256) ||
      !isBoundedIdentifier(input.expectedPollingDigest, 256) ||
      !isBoundedIdentifier(input.expectedTasknotesPkceChallenge, 128)
    ) {
      throw new DeviceSessionInputError();
    }
    const now = validatedNow(this.#clock);
    const generated = await generateCredential(this.#pepper, this.#random);
    const idleExpiresAt = now + IDLE_LIFETIME_SECONDS;
    const absoluteExpiresAt = now + ABSOLUTE_LIFETIME_SECONDS;

    const insert = this.#db
      .prepare(
        `INSERT INTO device_sessions (
          id, principal_id, credential_hash, device_name, client_kind, created_at,
          last_used_at, idle_expires_at, absolute_expires_at, revoked_at,
          redemption_transaction_id
        )
        SELECT ?, transaction_record.authorized_principal_id, ?, transaction_record.device_name,
               transaction_record.client_kind, ?, ?, ?, ?, NULL, transaction_record.id
        FROM oauth_transactions AS transaction_record
        JOIN principals AS principal ON principal.id = transaction_record.authorized_principal_id
        WHERE transaction_record.id = ?
          AND transaction_record.intent = 'sign_in'
          AND transaction_record.status = 'authorized'
          AND transaction_record.polling_secret_hash = ?
          AND transaction_record.tasknotes_pkce_challenge = ?
          AND transaction_record.expires_at > ?
          AND transaction_record.authorized_principal_id IS NOT NULL
        RETURNING id, device_name, client_kind, created_at, last_used_at,
                  idle_expires_at, absolute_expires_at, revoked_at`,
      )
      .bind(
        generated.id,
        generated.digest,
        now,
        now,
        idleExpiresAt,
        absoluteExpiresAt,
        input.transactionId,
        input.expectedPollingDigest,
        input.expectedTasknotesPkceChallenge,
        now,
      );
    const consume = this.#db
      .prepare(
        `UPDATE oauth_transactions
         SET status = 'consumed', consumed_at = ?
         WHERE id = ?
           AND intent = 'sign_in'
           AND status = 'authorized'
           AND polling_secret_hash = ?
           AND tasknotes_pkce_challenge = ?
           AND expires_at > ?
           AND authorized_principal_id IS NOT NULL
           AND EXISTS (
             SELECT 1
             FROM device_sessions
             WHERE id = ?
               AND redemption_transaction_id = oauth_transactions.id
               AND principal_id = oauth_transactions.authorized_principal_id
           )`,
      )
      .bind(
        now,
        input.transactionId,
        input.expectedPollingDigest,
        input.expectedTasknotesPkceChallenge,
        now,
        generated.id,
      );

    const [insertResult, consumeResult] = await this.#db.batch<MetadataRow>([insert, consume]);
    const insertedRow = insertResult?.results[0];
    if (
      insertResult?.meta.changes !== 1 ||
      consumeResult?.meta.changes !== 1 ||
      insertResult.results.length !== 1 ||
      insertedRow === undefined
    ) {
      return null;
    }

    return {
      ...metadata(insertedRow),
      credential: generated.credential,
    };
  }

  public async authenticate(credential: string): Promise<AuthenticatedDeviceSession | null> {
    if (typeof credential !== "string") {
      return null;
    }
    const parsed = parseServiceCredential(credential);
    if (parsed === null) {
      return null;
    }

    const id = encodeBase64Url(parsed.sessionId);
    const actualDigest = await credentialDigest(this.#pepper, parsed.sessionId, parsed.secret);
    const row = await this.#db
      .prepare(
        `SELECT s.id, s.principal_id, s.credential_hash, s.device_name, s.client_kind,
                s.created_at, s.last_used_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
         FROM device_sessions s
         JOIN principals p ON p.id = s.principal_id
         WHERE s.id = ?
         LIMIT 1`,
      )
      .bind(id)
      .first<SessionRow>();

    let expectedDigest: Uint8Array = new Uint8Array(DIGEST_BYTES);
    if (row !== null) {
      try {
        expectedDigest = decodeBase64Url(row.credential_hash, {
          minBytes: DIGEST_BYTES,
          maxBytes: DIGEST_BYTES,
        });
      } catch {
        expectedDigest = new Uint8Array(DIGEST_BYTES);
      }
    }
    const digestMatches = constantTimeEqual(actualDigest, expectedDigest);
    if (row === null || !digestMatches) {
      return null;
    }

    const now = validatedNow(this.#clock);
    if (row.revoked_at !== null || now >= row.idle_expires_at || now >= row.absolute_expires_at) {
      return null;
    }

    let authenticatedRow = row;
    if (now - row.last_used_at >= LAST_USED_UPDATE_INTERVAL_SECONDS) {
      const lastUsedAt = now;
      const idleExpiresAt = Math.min(now + IDLE_LIFETIME_SECONDS, row.absolute_expires_at);
      const update = await this.#db
        .prepare(
          `UPDATE device_sessions
           SET last_used_at = ?, idle_expires_at = ?
           WHERE id = ? AND principal_id = ? AND revoked_at IS NULL
             AND idle_expires_at > ? AND absolute_expires_at > ?
             AND last_used_at <= ?
             AND EXISTS (
               SELECT 1 FROM principals p
               WHERE p.id = device_sessions.principal_id
             )`,
        )
        .bind(
          lastUsedAt,
          idleExpiresAt,
          row.id,
          row.principal_id,
          lastUsedAt,
          lastUsedAt,
          now - LAST_USED_UPDATE_INTERVAL_SECONDS,
        )
        .run();
      if (update.meta.changes !== 1) {
        return null;
      }
      authenticatedRow = { ...row, last_used_at: lastUsedAt, idle_expires_at: idleExpiresAt };
    }

    return { principalId: row.principal_id, session: metadata(authenticatedRow) };
  }

  public async list(principalId: string): Promise<readonly DeviceSessionMetadata[]> {
    validatePrincipalId(principalId);
    const result = await this.#db
      .prepare(
        `SELECT s.id, s.device_name, s.client_kind, s.created_at, s.last_used_at,
                s.idle_expires_at, s.absolute_expires_at, s.revoked_at
         FROM device_sessions s
         JOIN principals p ON p.id = s.principal_id
         WHERE s.principal_id = ?
         ORDER BY s.created_at DESC, s.id DESC`,
      )
      .bind(principalId)
      .all<MetadataRow>();
    return result.results.map(metadata);
  }

  public async revoke(principalId: string, sessionId: string): Promise<boolean> {
    validatePrincipalId(principalId);
    if (!isBoundedIdentifier(sessionId, 64)) {
      return false;
    }
    const revokedAt = validatedNow(this.#clock);
    const result = await this.#db
      .prepare(
        `UPDATE device_sessions
         SET revoked_at = ?
         WHERE id = ? AND principal_id = ? AND revoked_at IS NULL
           AND EXISTS (
             SELECT 1 FROM principals p
             WHERE p.id = device_sessions.principal_id
           )`,
      )
      .bind(revokedAt, sessionId, principalId)
      .run();
    return result.meta.changes === 1;
  }
}
