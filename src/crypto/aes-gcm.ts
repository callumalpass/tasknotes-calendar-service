import { asArrayBuffer } from "./digest";

export async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length !== 32) {
    throw new TypeError("AES-256 key must be exactly 32 bytes");
  }
  return crypto.subtle.importKey("raw", asArrayBuffer(rawKey), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function aesEncrypt(
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

export async function aesDecrypt(
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
