import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { randomBytes, webCryptoRandom } from "./random";
import type { RandomByteSource } from "./random";

const CURSOR_VERSION = 1 as const;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_CURSOR_BYTES = 4096;
const MAX_PAGE_TOKEN_BYTES = 2048;
const MAX_LIFETIME_SECONDS = 600;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export interface EventCursorBinding {
  readonly principalId: string;
  readonly connectionId: string;
  readonly connectionGeneration: number;
  readonly calendarId: string;
  readonly rangeStart: string;
  readonly rangeEnd: string;
}

interface EventCursorPayload {
  readonly pageToken: string;
  readonly expiresAtEpochSeconds: number;
}

export class CursorError extends Error {
  public constructor() {
    super("cursor is invalid or expired");
    this.name = "CursorError";
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function assertBoundedText(value: string, name: string, maximumBytes: number): void {
  if (value.length === 0 || textEncoder.encode(value).length > maximumBytes) {
    throw new TypeError(`${name} is invalid`);
  }
}

function validateBinding(binding: EventCursorBinding): void {
  assertBoundedText(binding.principalId, "principalId", 256);
  assertBoundedText(binding.connectionId, "connectionId", 256);
  if (!Number.isSafeInteger(binding.connectionGeneration) || binding.connectionGeneration < 1) {
    throw new TypeError("connectionGeneration is invalid");
  }
  assertBoundedText(binding.calendarId, "calendarId", 256);
  assertBoundedText(binding.rangeStart, "rangeStart", 64);
  assertBoundedText(binding.rangeEnd, "rangeEnd", 64);
}

function associatedData(binding: EventCursorBinding): Uint8Array {
  validateBinding(binding);
  return textEncoder.encode(
    JSON.stringify({
      version: CURSOR_VERSION,
      purpose: "event-page",
      ...binding,
    }),
  );
}

async function importKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length !== KEY_BYTES) {
    throw new TypeError("cursor key must be exactly 32 bytes");
  }
  return crypto.subtle.importKey("raw", asArrayBuffer(rawKey), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

function parsePayload(value: unknown, nowEpochSeconds: number): EventCursorPayload {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    !("pageToken" in value) ||
    !("expiresAtEpochSeconds" in value) ||
    typeof value.pageToken !== "string" ||
    typeof value.expiresAtEpochSeconds !== "number"
  ) {
    throw new TypeError("cursor payload is invalid");
  }

  assertBoundedText(value.pageToken, "pageToken", MAX_PAGE_TOKEN_BYTES);
  if (
    !Number.isSafeInteger(value.expiresAtEpochSeconds) ||
    value.expiresAtEpochSeconds <= nowEpochSeconds ||
    value.expiresAtEpochSeconds > nowEpochSeconds + MAX_LIFETIME_SECONDS
  ) {
    throw new TypeError("cursor expiry is invalid");
  }

  return {
    pageToken: value.pageToken,
    expiresAtEpochSeconds: value.expiresAtEpochSeconds,
  };
}

export async function sealEventCursor(
  pageToken: string,
  binding: EventCursorBinding,
  nowEpochSeconds: number,
  rawKey: Uint8Array,
  random: RandomByteSource = webCryptoRandom,
): Promise<string> {
  try {
    assertBoundedText(pageToken, "pageToken", MAX_PAGE_TOKEN_BYTES);
    if (!Number.isSafeInteger(nowEpochSeconds) || nowEpochSeconds < 0) {
      throw new TypeError("current time is invalid");
    }
    const expiresAtEpochSeconds = nowEpochSeconds + MAX_LIFETIME_SECONDS;
    const iv = randomBytes(random, IV_BYTES);
    const plaintext = textEncoder.encode(JSON.stringify({ pageToken, expiresAtEpochSeconds }));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: asArrayBuffer(iv),
          additionalData: asArrayBuffer(associatedData(binding)),
          tagLength: 128,
        },
        await importKey(rawKey),
        asArrayBuffer(plaintext),
      ),
    );
    return `c1.${encodeBase64Url(iv)}.${encodeBase64Url(ciphertext)}`;
  } catch {
    throw new CursorError();
  }
}

export async function openEventCursor(
  cursor: string,
  binding: EventCursorBinding,
  nowEpochSeconds: number,
  rawKey: Uint8Array,
): Promise<string> {
  try {
    if (cursor.length === 0 || cursor.length > MAX_CURSOR_BYTES) {
      throw new TypeError("cursor length is invalid");
    }
    if (!Number.isSafeInteger(nowEpochSeconds) || nowEpochSeconds < 0) {
      throw new TypeError("current time is invalid");
    }
    const parts = cursor.split(".");
    if (parts.length !== 3 || parts[0] !== "c1") {
      throw new TypeError("cursor format is invalid");
    }
    const iv = decodeBase64Url(parts[1] ?? "", { minBytes: IV_BYTES, maxBytes: IV_BYTES });
    const ciphertext = decodeBase64Url(parts[2] ?? "", {
      minBytes: TAG_BYTES + 1,
      maxBytes: MAX_CURSOR_BYTES,
    });
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(associatedData(binding)),
        tagLength: 128,
      },
      await importKey(rawKey),
      asArrayBuffer(ciphertext),
    );
    return parsePayload(JSON.parse(textDecoder.decode(plaintext)) as unknown, nowEpochSeconds)
      .pageToken;
  } catch {
    throw new CursorError();
  }
}
