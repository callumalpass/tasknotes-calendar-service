import { hasExactKeys, isRecord } from "../contracts/common";
import { aesDecrypt, aesEncrypt, importAesKey } from "./aes-gcm";
import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { randomBytes, webCryptoRandom } from "./random";
import type { RandomByteSource } from "./random";

const ENVELOPE_SCHEMA_VERSION = 1 as const;
const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MAX_TOKEN_BYTES = 16_384;
const MAX_PAYLOAD_CIPHERTEXT_BYTES = 65_536;
const MAX_PAYLOAD_PLAINTEXT_BYTES = MAX_PAYLOAD_CIPHERTEXT_BYTES - GCM_TAG_BYTES;
const MAX_SCOPES = 100;
const MAX_SCOPE_BYTES = 256;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export interface TokenPayload {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAtEpochSeconds: number;
  readonly scopes: readonly string[];
}

export interface TokenEnvelopeContext {
  readonly environment: string;
  readonly provider: "google";
  readonly principalId: string;
  readonly connectionId: string;
  readonly connectionGeneration: number;
  readonly tokenVersion: number;
  readonly tokenKind: string;
}

export interface TokenEnvelope {
  readonly schemaVersion: 1;
  readonly keyVersion: number;
  readonly dekIv: string;
  readonly wrappedDek: string;
  readonly payloadIv: string;
  readonly ciphertext: string;
}

export interface KeyEncryptionKeyring {
  readonly activeVersion: number;
  readonly keys: ReadonlyMap<number, Uint8Array>;
}

export class TokenEnvelopeError extends Error {
  public constructor() {
    super("token envelope is invalid or cannot be authenticated");
    this.name = "TokenEnvelopeError";
  }
}

function assertBoundedString(
  value: unknown,
  name: string,
  maximumBytes: number,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    textEncoder.encode(value).length > maximumBytes
  ) {
    throw new TypeError(`${name} is invalid`);
  }
}

function validateContext(context: TokenEnvelopeContext): void {
  assertBoundedString(context.environment, "environment", 64);
  const provider: unknown = context.provider;
  if (provider !== "google") {
    throw new TypeError("provider must be google");
  }
  assertBoundedString(context.principalId, "principalId", 256);
  assertBoundedString(context.connectionId, "connectionId", 256);
  if (!Number.isSafeInteger(context.connectionGeneration) || context.connectionGeneration < 1) {
    throw new TypeError("connectionGeneration is invalid");
  }
  if (!Number.isSafeInteger(context.tokenVersion) || context.tokenVersion < 1) {
    throw new TypeError("tokenVersion is invalid");
  }
  assertBoundedString(context.tokenKind, "tokenKind", 64);
}

function validatePayload(value: unknown): TokenPayload {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["accessToken", "refreshToken", "expiresAtEpochSeconds", "scopes"])
  ) {
    throw new TypeError("token payload has an invalid shape");
  }

  assertBoundedString(value["accessToken"], "accessToken", MAX_TOKEN_BYTES);
  assertBoundedString(value["refreshToken"], "refreshToken", MAX_TOKEN_BYTES);
  if (
    typeof value["expiresAtEpochSeconds"] !== "number" ||
    !Number.isSafeInteger(value["expiresAtEpochSeconds"]) ||
    value["expiresAtEpochSeconds"] < 0
  ) {
    throw new TypeError("expiresAtEpochSeconds is invalid");
  }
  if (!Array.isArray(value["scopes"]) || value["scopes"].length > MAX_SCOPES) {
    throw new TypeError("scopes are invalid");
  }

  const scopes = value["scopes"].map((scope) => {
    assertBoundedString(scope, "scope", MAX_SCOPE_BYTES);
    return scope;
  });

  return {
    accessToken: value["accessToken"],
    refreshToken: value["refreshToken"],
    expiresAtEpochSeconds: value["expiresAtEpochSeconds"],
    scopes,
  };
}

function validateVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new TypeError("key version is invalid");
  }
  return value;
}

function parseEnvelope(value: unknown): TokenEnvelope {
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
    value["schemaVersion"] !== ENVELOPE_SCHEMA_VERSION ||
    typeof value["dekIv"] !== "string" ||
    typeof value["wrappedDek"] !== "string" ||
    typeof value["payloadIv"] !== "string" ||
    typeof value["ciphertext"] !== "string"
  ) {
    throw new TypeError("token envelope has an invalid shape");
  }

  return {
    schemaVersion: ENVELOPE_SCHEMA_VERSION,
    keyVersion: validateVersion(value["keyVersion"]),
    dekIv: value["dekIv"],
    wrappedDek: value["wrappedDek"],
    payloadIv: value["payloadIv"],
    ciphertext: value["ciphertext"],
  };
}

function associatedData(context: TokenEnvelopeContext, purpose: "payload"): Uint8Array;
function associatedData(
  context: TokenEnvelopeContext,
  purpose: "dek",
  keyVersion: number,
): Uint8Array;
function associatedData(
  context: TokenEnvelopeContext,
  purpose: "dek" | "payload",
  keyVersion?: number,
): Uint8Array {
  const common = {
    environment: context.environment,
    provider: context.provider,
    principalId: context.principalId,
    connectionId: context.connectionId,
    connectionGeneration: context.connectionGeneration,
    tokenVersion: context.tokenVersion,
    tokenKind: context.tokenKind,
    schemaVersion: ENVELOPE_SCHEMA_VERSION,
    purpose,
  };
  return textEncoder.encode(JSON.stringify(purpose === "dek" ? { ...common, keyVersion } : common));
}

function getKek(keyring: KeyEncryptionKeyring, version: number): Uint8Array {
  validateVersion(version);
  const key = keyring.keys.get(version);
  if (key?.length !== AES_KEY_BYTES) {
    throw new TypeError("key version is unavailable");
  }
  return key;
}

async function unwrapDek(
  envelope: TokenEnvelope,
  context: TokenEnvelopeContext,
  keyring: KeyEncryptionKeyring,
): Promise<Uint8Array> {
  const kek = await importAesKey(getKek(keyring, envelope.keyVersion));
  const iv = decodeBase64Url(envelope.dekIv, { minBytes: GCM_IV_BYTES, maxBytes: GCM_IV_BYTES });
  const wrapped = decodeBase64Url(envelope.wrappedDek, {
    minBytes: AES_KEY_BYTES + GCM_TAG_BYTES,
    maxBytes: AES_KEY_BYTES + GCM_TAG_BYTES,
  });
  const dek = await aesDecrypt(
    kek,
    wrapped,
    iv,
    associatedData(context, "dek", envelope.keyVersion),
  );
  if (dek.length !== AES_KEY_BYTES) {
    throw new TypeError("unwrapped key has an invalid size");
  }
  return dek;
}

async function decryptPayload(
  envelope: TokenEnvelope,
  context: TokenEnvelopeContext,
  dek: Uint8Array,
): Promise<TokenPayload> {
  const iv = decodeBase64Url(envelope.payloadIv, {
    minBytes: GCM_IV_BYTES,
    maxBytes: GCM_IV_BYTES,
  });
  const ciphertext = decodeBase64Url(envelope.ciphertext, {
    minBytes: GCM_TAG_BYTES + 1,
    maxBytes: MAX_PAYLOAD_CIPHERTEXT_BYTES,
  });
  const plaintext = await aesDecrypt(
    await importAesKey(dek),
    ciphertext,
    iv,
    associatedData(context, "payload"),
  );
  return validatePayload(JSON.parse(textDecoder.decode(plaintext)) as unknown);
}

export async function encryptTokenEnvelope(
  payload: TokenPayload,
  context: TokenEnvelopeContext,
  keyring: KeyEncryptionKeyring,
  random: RandomByteSource = webCryptoRandom,
): Promise<TokenEnvelope> {
  try {
    validateContext(context);
    const validatedPayload = validatePayload(payload);
    const keyVersion = validateVersion(keyring.activeVersion);
    const kek = await importAesKey(getKek(keyring, keyVersion));
    const dek = randomBytes(random, AES_KEY_BYTES);
    const dekIv = randomBytes(random, GCM_IV_BYTES);
    const payloadIv = randomBytes(random, GCM_IV_BYTES);
    const wrappedDek = await aesEncrypt(
      kek,
      dek,
      dekIv,
      associatedData(context, "dek", keyVersion),
    );
    const serializedPayload = textEncoder.encode(JSON.stringify(validatedPayload));
    if (serializedPayload.length > MAX_PAYLOAD_PLAINTEXT_BYTES) {
      throw new TypeError("serialized token payload is too large");
    }
    const ciphertext = await aesEncrypt(
      await importAesKey(dek),
      serializedPayload,
      payloadIv,
      associatedData(context, "payload"),
    );

    return {
      schemaVersion: ENVELOPE_SCHEMA_VERSION,
      keyVersion,
      dekIv: encodeBase64Url(dekIv),
      wrappedDek: encodeBase64Url(wrappedDek),
      payloadIv: encodeBase64Url(payloadIv),
      ciphertext: encodeBase64Url(ciphertext),
    };
  } catch {
    throw new TokenEnvelopeError();
  }
}

export async function decryptTokenEnvelope(
  value: unknown,
  context: TokenEnvelopeContext,
  keyring: KeyEncryptionKeyring,
): Promise<TokenPayload> {
  try {
    validateContext(context);
    const envelope = parseEnvelope(value);
    const dek = await unwrapDek(envelope, context, keyring);
    return await decryptPayload(envelope, context, dek);
  } catch {
    throw new TokenEnvelopeError();
  }
}

export async function rewrapTokenEnvelope(
  value: unknown,
  context: TokenEnvelopeContext,
  keyring: KeyEncryptionKeyring,
  random: RandomByteSource = webCryptoRandom,
): Promise<TokenEnvelope> {
  try {
    validateContext(context);
    const envelope = parseEnvelope(value);
    const activeVersion = validateVersion(keyring.activeVersion);
    if (activeVersion <= envelope.keyVersion) {
      throw new TypeError("rewrap requires a newer active key version");
    }

    const dek = await unwrapDek(envelope, context, keyring);
    await decryptPayload(envelope, context, dek);
    const dekIv = randomBytes(random, GCM_IV_BYTES);
    const wrappedDek = await aesEncrypt(
      await importAesKey(getKek(keyring, activeVersion)),
      dek,
      dekIv,
      associatedData(context, "dek", activeVersion),
    );

    return {
      ...envelope,
      keyVersion: activeVersion,
      dekIv: encodeBase64Url(dekIv),
      wrappedDek: encodeBase64Url(wrappedDek),
    };
  } catch {
    throw new TokenEnvelopeError();
  }
}
