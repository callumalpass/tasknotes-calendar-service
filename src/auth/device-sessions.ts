import { decodeBase64Url, encodeBase64Url } from "../crypto/base64url";
import { constantTimeEqual } from "../crypto/digest";
import { randomBytes } from "../crypto/random";
import type { RandomByteSource } from "../crypto/random";

const CREDENTIAL_VERSION = "v1";
const SESSION_ID_BYTES = 16;
const CREDENTIAL_SECRET_BYTES = 32;
const DIGEST_BYTES = 32;
const IDLE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1_000;
const ABSOLUTE_LIFETIME_MS = 90 * 24 * 60 * 60 * 1_000;
const LAST_USED_UPDATE_INTERVAL_MS = 60 * 60 * 1_000;
const MAX_DEVICE_NAME_BYTES = 128;
const MAX_PRINCIPAL_ID_BYTES = 256;
const CLIENT_KINDS = ["web", "ios", "android", "obsidian"] as const;
const textEncoder = new TextEncoder();

export type DeviceClientKind = (typeof CLIENT_KINDS)[number];

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
  created_at: string;
  last_used_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
}

interface MetadataRow {
  id: string;
  device_name: string;
  client_kind: string;
  created_at: string;
  last_used_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
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

function validatedNow(clock: Clock): Date {
  const now = clock.now();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError("clock returned an invalid date");
  }
  return new Date(now.getTime());
}

function isBoundedIdentifier(value: string, maximumBytes: number): boolean {
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
  if (
    !isBoundedIdentifier(deviceName, MAX_DEVICE_NAME_BYTES) ||
    deviceName.trim() !== deviceName ||
    !CLIENT_KINDS.some((candidate) => candidate === clientKind)
  ) {
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

function parseCredential(credential: string): { sessionId: Uint8Array; secret: Uint8Array } | null {
  if (credential.length > 80) {
    return null;
  }
  const parts = credential.split(".");
  if (parts.length !== 3 || parts[0] !== CREDENTIAL_VERSION) {
    return null;
  }
  try {
    return {
      sessionId: decodeBase64Url(parts[1] ?? "", {
        minBytes: SESSION_ID_BYTES,
        maxBytes: SESSION_ID_BYTES,
      }),
      secret: decodeBase64Url(parts[2] ?? "", {
        minBytes: CREDENTIAL_SECRET_BYTES,
        maxBytes: CREDENTIAL_SECRET_BYTES,
      }),
    };
  } catch {
    return null;
  }
}

function isClientKind(value: string): value is DeviceClientKind {
  return CLIENT_KINDS.some((candidate) => candidate === value);
}

function metadata(row: MetadataRow | SessionRow): DeviceSessionMetadata {
  if (!isClientKind(row.client_kind)) {
    throw new Error("stored device session has an invalid client kind");
  }
  return {
    id: row.id,
    deviceName: row.device_name,
    clientKind: row.client_kind,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    idleExpiresAt: row.idle_expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    revokedAt: row.revoked_at,
  };
}

function validStoredInstant(value: string): number | null {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? milliseconds : null;
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
    const sessionIdBytes = randomBytes(this.#random, SESSION_ID_BYTES);
    const secret = randomBytes(this.#random, CREDENTIAL_SECRET_BYTES);
    const id = encodeBase64Url(sessionIdBytes);
    const credential = `${CREDENTIAL_VERSION}.${id}.${encodeBase64Url(secret)}`;
    const digest = encodeBase64Url(await credentialDigest(this.#pepper, sessionIdBytes, secret));
    const createdAt = now.toISOString();
    const idleExpiresAt = new Date(now.getTime() + IDLE_LIFETIME_MS).toISOString();
    const absoluteExpiresAt = new Date(now.getTime() + ABSOLUTE_LIFETIME_MS).toISOString();

    const result = await this.#db
      .prepare(
        `INSERT INTO device_sessions (
          id, principal_id, credential_hash, device_name, client_kind, created_at,
          last_used_at, idle_expires_at, absolute_expires_at, revoked_at
        )
        SELECT ?, id, ?, ?, ?, ?, ?, ?, ?, NULL
        FROM principals
        WHERE id = ? AND state = 'active'`,
      )
      .bind(
        id,
        digest,
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
      id,
      credential,
      deviceName: input.deviceName,
      clientKind: input.clientKind,
      createdAt,
      lastUsedAt: createdAt,
      idleExpiresAt,
      absoluteExpiresAt,
      revokedAt: null,
    };
  }

  public async authenticate(credential: string): Promise<AuthenticatedDeviceSession | null> {
    if (typeof credential !== "string") {
      return null;
    }
    const parsed = parseCredential(credential);
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
         JOIN principals p ON p.id = s.principal_id AND p.state = 'active'
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
    const nowMs = now.getTime();
    const lastUsedMs = validStoredInstant(row.last_used_at);
    const idleExpiresMs = validStoredInstant(row.idle_expires_at);
    const absoluteExpiresMs = validStoredInstant(row.absolute_expires_at);
    if (
      row.revoked_at !== null ||
      lastUsedMs === null ||
      idleExpiresMs === null ||
      absoluteExpiresMs === null ||
      nowMs >= idleExpiresMs ||
      nowMs >= absoluteExpiresMs
    ) {
      return null;
    }

    let authenticatedRow = row;
    if (nowMs - lastUsedMs >= LAST_USED_UPDATE_INTERVAL_MS) {
      const lastUsedAt = now.toISOString();
      const idleExpiresAt = new Date(
        Math.min(nowMs + IDLE_LIFETIME_MS, absoluteExpiresMs),
      ).toISOString();
      const update = await this.#db
        .prepare(
          `UPDATE device_sessions
           SET last_used_at = ?, idle_expires_at = ?
           WHERE id = ? AND principal_id = ? AND revoked_at IS NULL
             AND idle_expires_at > ? AND absolute_expires_at > ?
             AND last_used_at <= ?
             AND EXISTS (
               SELECT 1 FROM principals p
               WHERE p.id = device_sessions.principal_id AND p.state = 'active'
             )`,
        )
        .bind(
          lastUsedAt,
          idleExpiresAt,
          row.id,
          row.principal_id,
          lastUsedAt,
          lastUsedAt,
          new Date(nowMs - LAST_USED_UPDATE_INTERVAL_MS).toISOString(),
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
         JOIN principals p ON p.id = s.principal_id AND p.state = 'active'
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
    const revokedAt = validatedNow(this.#clock).toISOString();
    const result = await this.#db
      .prepare(
        `UPDATE device_sessions
         SET revoked_at = ?
         WHERE id = ? AND principal_id = ? AND revoked_at IS NULL
           AND EXISTS (
             SELECT 1 FROM principals p
             WHERE p.id = device_sessions.principal_id AND p.state = 'active'
           )`,
      )
      .bind(revokedAt, sessionId, principalId)
      .run();
    return result.meta.changes === 1;
  }
}
