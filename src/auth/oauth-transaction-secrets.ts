import { decodeBase64Url, encodeBase64Url } from "../crypto/base64url";
import { isValidPkceVerifier } from "../crypto/pkce";
import { randomBytes, webCryptoRandom } from "../crypto/random";
import type { RandomByteSource } from "../crypto/random";
import type { KeyEncryptionKeyring } from "../crypto/token-envelope";

const SCHEMA_VERSION = 1 as const;
const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MIN_SERIALIZED_PAYLOAD_BYTES = 58;
const MAX_SERIALIZED_PAYLOAD_BYTES = 143;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export interface OAuthTransactionSecretContext {
  readonly environment: string;
  readonly transactionId: string;
  readonly intent: "sign_in" | "connect_calendar";
}

export interface OAuthTransactionProviderPkceEnvelope {
  readonly schemaVersion: 1;
  readonly keyVersion: number;
  readonly dekIv: string;
  readonly wrappedDek: string;
  readonly payloadIv: string;
  readonly ciphertext: string;
}

export interface OAuthTransactionProviderPkceRow {
  readonly provider_pkce_schema_version: number;
  readonly provider_pkce_key_version: number;
  readonly provider_pkce_dek_iv: string;
  readonly provider_pkce_wrapped_dek: string;
  readonly provider_pkce_payload_iv: string;
  readonly provider_pkce_ciphertext: string;
}

export class OAuthTransactionSecretError extends Error {
  public constructor() {
    super("OAuth transaction secret is invalid or cannot be authenticated");
    this.name = "OAuthTransactionSecretError";
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function assertBoundedString(value: unknown, maximumBytes: number): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    textEncoder.encode(value).length > maximumBytes
  ) {
    throw new TypeError("transaction secret context is invalid");
  }
}

function validateContext(context: OAuthTransactionSecretContext): void {
  assertBoundedString(context.environment, 64);
  assertBoundedString(context.transactionId, 256);
  const intent: unknown = context.intent;
  if (intent !== "sign_in" && intent !== "connect_calendar") {
    throw new TypeError("transaction intent is invalid");
  }
}

function validateKeyVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new TypeError("key version is invalid");
  }
  return value;
}

function parseEnvelope(value: unknown): OAuthTransactionProviderPkceEnvelope {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schemaVersion",
      "keyVersion",
      "dekIv",
      "wrappedDek",
      "payloadIv",
      "ciphertext",
    ]) ||
    value["schemaVersion"] !== SCHEMA_VERSION ||
    typeof value["dekIv"] !== "string" ||
    typeof value["wrappedDek"] !== "string" ||
    typeof value["payloadIv"] !== "string" ||
    typeof value["ciphertext"] !== "string"
  ) {
    throw new TypeError("transaction secret envelope has an invalid shape");
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    keyVersion: validateKeyVersion(value["keyVersion"]),
    dekIv: value["dekIv"],
    wrappedDek: value["wrappedDek"],
    payloadIv: value["payloadIv"],
    ciphertext: value["ciphertext"],
  };
}

function associatedData(
  context: OAuthTransactionSecretContext,
  purpose: "dek" | "payload",
  keyVersion?: number,
): Uint8Array {
  const common = {
    environment: context.environment,
    transactionId: context.transactionId,
    intent: context.intent,
    schemaVersion: SCHEMA_VERSION,
    purpose,
    tokenKind: "provider_pkce",
  };
  return textEncoder.encode(JSON.stringify(purpose === "dek" ? { ...common, keyVersion } : common));
}

function getKek(keyring: KeyEncryptionKeyring, version: number): Uint8Array {
  const key = keyring.keys.get(validateKeyVersion(version));
  if (key?.length !== AES_KEY_BYTES) {
    throw new TypeError("key version is unavailable");
  }
  return key;
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== AES_KEY_BYTES) throw new TypeError("AES-256 key has an invalid size");
  return crypto.subtle.importKey("raw", asArrayBuffer(raw), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptAesGcm(
  key: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(aad),
        tagLength: 128,
      },
      key,
      asArrayBuffer(plaintext),
    ),
  );
}

async function decryptAesGcm(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(aad),
        tagLength: 128,
      },
      key,
      asArrayBuffer(ciphertext),
    ),
  );
}

function serializeVerifier(verifier: string): Uint8Array {
  if (!isValidPkceVerifier(verifier)) throw new TypeError("provider PKCE verifier is invalid");
  return textEncoder.encode(JSON.stringify({ verifier }));
}

function parseVerifier(plaintext: Uint8Array): string {
  if (
    plaintext.length < MIN_SERIALIZED_PAYLOAD_BYTES ||
    plaintext.length > MAX_SERIALIZED_PAYLOAD_BYTES
  ) {
    throw new TypeError("provider PKCE payload has an invalid size");
  }
  const payload: unknown = JSON.parse(textDecoder.decode(plaintext));
  if (!isRecord(payload) || !hasExactKeys(payload, ["verifier"])) {
    throw new TypeError("provider PKCE payload has an invalid shape");
  }
  const verifier = payload["verifier"];
  if (typeof verifier !== "string" || !isValidPkceVerifier(verifier)) {
    throw new TypeError("provider PKCE verifier is invalid");
  }
  return verifier;
}

export function oauthTransactionProviderPkceEnvelopeToRow(
  value: OAuthTransactionProviderPkceEnvelope,
): OAuthTransactionProviderPkceRow {
  try {
    const envelope = parseEnvelope(value);
    return {
      provider_pkce_schema_version: envelope.schemaVersion,
      provider_pkce_key_version: envelope.keyVersion,
      provider_pkce_dek_iv: envelope.dekIv,
      provider_pkce_wrapped_dek: envelope.wrappedDek,
      provider_pkce_payload_iv: envelope.payloadIv,
      provider_pkce_ciphertext: envelope.ciphertext,
    };
  } catch {
    throw new OAuthTransactionSecretError();
  }
}

export function oauthTransactionProviderPkceEnvelopeFromRow(
  row: OAuthTransactionProviderPkceRow,
): OAuthTransactionProviderPkceEnvelope {
  try {
    return parseEnvelope({
      schemaVersion: row.provider_pkce_schema_version,
      keyVersion: row.provider_pkce_key_version,
      dekIv: row.provider_pkce_dek_iv,
      wrappedDek: row.provider_pkce_wrapped_dek,
      payloadIv: row.provider_pkce_payload_iv,
      ciphertext: row.provider_pkce_ciphertext,
    });
  } catch {
    throw new OAuthTransactionSecretError();
  }
}

export async function encryptOAuthTransactionProviderPkce(
  verifier: string,
  context: OAuthTransactionSecretContext,
  keyring: KeyEncryptionKeyring,
  random: RandomByteSource = webCryptoRandom,
): Promise<OAuthTransactionProviderPkceEnvelope> {
  try {
    validateContext(context);
    const plaintext = serializeVerifier(verifier);
    const keyVersion = validateKeyVersion(keyring.activeVersion);
    const kek = await importAesKey(getKek(keyring, keyVersion));
    const dek = randomBytes(random, AES_KEY_BYTES);
    const dekIv = randomBytes(random, GCM_IV_BYTES);
    const payloadIv = randomBytes(random, GCM_IV_BYTES);
    const wrappedDek = await encryptAesGcm(
      kek,
      dek,
      dekIv,
      associatedData(context, "dek", keyVersion),
    );
    const ciphertext = await encryptAesGcm(
      await importAesKey(dek),
      plaintext,
      payloadIv,
      associatedData(context, "payload"),
    );
    return {
      schemaVersion: SCHEMA_VERSION,
      keyVersion,
      dekIv: encodeBase64Url(dekIv),
      wrappedDek: encodeBase64Url(wrappedDek),
      payloadIv: encodeBase64Url(payloadIv),
      ciphertext: encodeBase64Url(ciphertext),
    };
  } catch {
    throw new OAuthTransactionSecretError();
  }
}

export async function decryptOAuthTransactionProviderPkce(
  value: unknown,
  context: OAuthTransactionSecretContext,
  keyring: KeyEncryptionKeyring,
): Promise<string> {
  try {
    validateContext(context);
    const envelope = parseEnvelope(value);
    const kek = await importAesKey(getKek(keyring, envelope.keyVersion));
    const dekIv = decodeBase64Url(envelope.dekIv, {
      minBytes: GCM_IV_BYTES,
      maxBytes: GCM_IV_BYTES,
    });
    const wrappedDek = decodeBase64Url(envelope.wrappedDek, {
      minBytes: AES_KEY_BYTES + GCM_TAG_BYTES,
      maxBytes: AES_KEY_BYTES + GCM_TAG_BYTES,
    });
    const dek = await decryptAesGcm(
      kek,
      wrappedDek,
      dekIv,
      associatedData(context, "dek", envelope.keyVersion),
    );
    if (dek.length !== AES_KEY_BYTES) throw new TypeError("unwrapped DEK has an invalid size");
    const payloadIv = decodeBase64Url(envelope.payloadIv, {
      minBytes: GCM_IV_BYTES,
      maxBytes: GCM_IV_BYTES,
    });
    const ciphertext = decodeBase64Url(envelope.ciphertext, {
      minBytes: MIN_SERIALIZED_PAYLOAD_BYTES + GCM_TAG_BYTES,
      maxBytes: MAX_SERIALIZED_PAYLOAD_BYTES + GCM_TAG_BYTES,
    });
    const plaintext = await decryptAesGcm(
      await importAesKey(dek),
      ciphertext,
      payloadIv,
      associatedData(context, "payload"),
    );
    return parseVerifier(plaintext);
  } catch {
    throw new OAuthTransactionSecretError();
  }
}
