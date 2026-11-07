import { encodeBase64Url } from "../crypto/base64url";
import { asArrayBuffer } from "../crypto/digest";

const PROVIDER = "google";
const ISSUER = "https://accounts.google.com";
const HMAC_KEY_BYTES = 32;
const MAX_SUBJECT_BYTES = 255;
const MAX_DATABASE_ID_BYTES = 256;
const DOMAIN = "tasknotes-calendar.identity-deletion-fence.v1";
const textEncoder = new TextEncoder();

export interface GoogleIdentityTuple {
  readonly provider: string;
  readonly issuer: string;
  readonly subject: string;
}

export interface IdentityDeletionDependencies {
  readonly db: D1Database;
  readonly hmacKey: Uint8Array;
  readonly nowEpochSeconds: () => number;
}

export interface DeleteIdentityInput {
  readonly authenticatedPrincipalId: string;
  readonly identityId: string;
  readonly identity: GoogleIdentityTuple;
}

export type IdentityDeletionResult = "completed" | "unavailable";

export class IdentityDeletionInputError extends Error {
  public constructor() {
    super("identity deletion input is invalid");
    this.name = "IdentityDeletionInputError";
  }
}

function isBoundedValue(value: string, maximumBytes: number): boolean {
  if (value.length === 0 || textEncoder.encode(value).length > maximumBytes) {
    return false;
  }
  return !Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function validateIdentity(identity: GoogleIdentityTuple): void {
  if (
    identity.provider !== PROVIDER ||
    identity.issuer !== ISSUER ||
    !isBoundedValue(identity.subject, MAX_SUBJECT_BYTES)
  ) {
    throw new IdentityDeletionInputError();
  }
}

function validateDatabaseId(value: string): void {
  if (!isBoundedValue(value, MAX_DATABASE_ID_BYTES)) {
    throw new IdentityDeletionInputError();
  }
}

function validateEpochSeconds(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new IdentityDeletionInputError();
  }
}

function lengthPrefixed(value: string): Uint8Array {
  const encoded = textEncoder.encode(value);
  const result = new Uint8Array(2 + encoded.length);
  new DataView(result.buffer).setUint16(0, encoded.length, false);
  result.set(encoded, 2);
  return result;
}

function digestMessage(identity: GoogleIdentityTuple): Uint8Array {
  const fields = [DOMAIN, identity.provider, identity.issuer, identity.subject].map(lengthPrefixed);
  const length = fields.reduce((total, field) => total + field.length, 1);
  const message = new Uint8Array(length);
  message[0] = 1;
  let offset = 1;
  for (const field of fields) {
    message.set(field, offset);
    offset += field.length;
  }
  return message;
}

async function identityDigest(key: Uint8Array, identity: GoogleIdentityTuple): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    asArrayBuffer(digestMessage(identity)),
  );
  return encodeBase64Url(new Uint8Array(digest));
}

export class IdentityDeletion {
  readonly #db: D1Database;
  readonly #hmacKey: Uint8Array;
  readonly #nowEpochSeconds: () => number;

  public constructor(dependencies: IdentityDeletionDependencies) {
    if (dependencies.hmacKey.length !== HMAC_KEY_BYTES) {
      throw new TypeError("identity deletion HMAC key must be exactly 32 bytes");
    }
    this.#db = dependencies.db;
    this.#hmacKey = Uint8Array.from(dependencies.hmacKey);
    this.#nowEpochSeconds = dependencies.nowEpochSeconds;
  }

  public async fenceDigest(identity: GoogleIdentityTuple): Promise<string> {
    validateIdentity(identity);
    return identityDigest(this.#hmacKey, identity);
  }

  public async deletePrincipal(input: DeleteIdentityInput): Promise<IdentityDeletionResult> {
    validateDatabaseId(input.authenticatedPrincipalId);
    validateDatabaseId(input.identityId);
    validateIdentity(input.identity);
    const deletedAt = this.#nowEpochSeconds();
    validateEpochSeconds(deletedAt);
    const digest = await identityDigest(this.#hmacKey, input.identity);
    const identityBindings = [
      input.identityId,
      input.authenticatedPrincipalId,
      input.identity.provider,
      input.identity.issuer,
      input.identity.subject,
    ] as const;

    const fence = this.#db
      .prepare(
        `INSERT INTO identity_deletion_fences (identity_digest, deleted_at)
         SELECT ?, ?
         WHERE EXISTS (
           SELECT 1 FROM external_identities
           WHERE id = ? AND principal_id = ? AND provider = ? AND issuer = ? AND subject = ?
         ) OR (
           EXISTS (
             SELECT 1 FROM identity_deletion_fences WHERE identity_digest = ?
           ) AND NOT EXISTS (
             SELECT 1 FROM external_identities
             WHERE provider = ? AND issuer = ? AND subject = ?
           )
         )
         ON CONFLICT(identity_digest) DO UPDATE SET
           deleted_at = MAX(identity_deletion_fences.deleted_at, excluded.deleted_at)`,
      )
      .bind(
        digest,
        deletedAt,
        ...identityBindings,
        digest,
        input.identity.provider,
        input.identity.issuer,
        input.identity.subject,
      );
    const deletion = this.#db
      .prepare(
        `DELETE FROM principals
         WHERE id = ? AND EXISTS (
           SELECT 1 FROM external_identities
           WHERE id = ? AND principal_id = principals.id
             AND provider = ? AND issuer = ? AND subject = ?
         )`,
      )
      .bind(
        input.authenticatedPrincipalId,
        input.identityId,
        input.identity.provider,
        input.identity.issuer,
        input.identity.subject,
      );

    const results = await this.#db.batch([fence, deletion]);
    const fenceResult = results[0];
    if (fenceResult === undefined) {
      throw new Error("identity deletion batch returned no fence result");
    }
    return fenceResult.meta.changes === 1 ? "completed" : "unavailable";
  }
}
