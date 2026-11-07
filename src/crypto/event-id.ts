import { decodeBase64Url, encodeBase64Url } from "./base64url";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export interface EventIdBinding {
  readonly environment: "local" | "lab" | "staging" | "production";
  readonly provider: "google";
  readonly authorizationScopedCalendarId: string;
}

async function subkey(rawKey: Uint8Array, purpose: string, algorithm: "HMAC" | "AES-GCM") {
  if (rawKey.byteLength !== 32) throw new TypeError("event ID key must be 32 bytes");
  const key = await crypto.subtle.importKey("raw", Uint8Array.from(rawKey), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode(purpose) },
    key,
    algorithm === "HMAC"
      ? { name: "HMAC", hash: "SHA-256", length: 256 }
      : { name: "AES-GCM", length: 256 },
    false,
    algorithm === "HMAC" ? ["sign"] : ["encrypt", "decrypt"],
  );
}

function tuple(binding: EventIdBinding): string[] {
  return [
    "event-id",
    "1",
    binding.environment,
    binding.provider,
    binding.authorizationScopedCalendarId,
  ];
}

export async function sealEventId(
  providerId: string,
  binding: EventIdBinding,
  rawKey: Uint8Array,
): Promise<string> {
  const plaintext = encoder.encode(providerId);
  if (plaintext.length === 0 || plaintext.length > 1024) throw new TypeError("invalid event ID");
  const iv = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      await subkey(rawKey, "event-id-mac-v1", "HMAC"),
      encoder.encode(JSON.stringify([...tuple(binding), providerId])),
    ),
  ).slice(0, 12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode(JSON.stringify(tuple(binding))) },
      await subkey(rawKey, "event-id-encryption-v1", "AES-GCM"),
      plaintext,
    ),
  );
  const sealed = new Uint8Array(iv.length + ciphertext.length);
  sealed.set(iv);
  sealed.set(ciphertext, iv.length);
  return `e1_${encodeBase64Url(sealed)}`;
}

export async function openEventId(
  sealed: string,
  binding: EventIdBinding,
  rawKey: Uint8Array,
): Promise<string> {
  if (!sealed.startsWith("e1_")) throw new TypeError("invalid event ID");
  const bytes = decodeBase64Url(sealed.slice(3), { minBytes: 29, maxBytes: 1052 });
  return decoder.decode(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: Uint8Array.from(bytes.subarray(0, 12)),
        additionalData: encoder.encode(JSON.stringify(tuple(binding))),
      },
      await subkey(rawKey, "event-id-encryption-v1", "AES-GCM"),
      Uint8Array.from(bytes.subarray(12)),
    ),
  );
}

export async function createProviderEventId(
  principalId: string,
  idempotencyKey: string,
  binding: EventIdBinding,
  rawKey: Uint8Array,
): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      await subkey(rawKey, "event-create-v1", "HMAC"),
      encoder.encode(JSON.stringify([...tuple(binding), principalId, idempotencyKey])),
    ),
  );
  const alphabet = "0123456789abcdefghijklmnopqrstuv";
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of digest) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet.charAt((value >>> bits) & 31);
    }
  }
  if (bits > 0) result += alphabet.charAt((value << (5 - bits)) & 31);
  return result;
}
