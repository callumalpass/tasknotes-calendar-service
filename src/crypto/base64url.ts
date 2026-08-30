const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export interface Base64UrlDecodeLimits {
  readonly minBytes?: number;
  readonly maxBytes: number;
}

function assertByteLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(encoded: string, limits: Base64UrlDecodeLimits): Uint8Array {
  const minBytes = limits.minBytes ?? 0;
  assertByteLimit(minBytes, "minBytes");
  assertByteLimit(limits.maxBytes, "maxBytes");
  if (minBytes > limits.maxBytes) {
    throw new TypeError("minBytes must not exceed maxBytes");
  }

  const maximumEncodedLength = Math.ceil((limits.maxBytes * 4) / 3);
  if (encoded.length > maximumEncodedLength) {
    throw new RangeError("decoded base64url size is outside the permitted range");
  }
  if (!BASE64URL_PATTERN.test(encoded) || encoded.length % 4 === 1) {
    throw new TypeError("value is not canonical base64url");
  }

  const remainder = encoded.length % 4;
  const decodedLength = Math.floor(encoded.length / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
  if (decodedLength < minBytes || decodedLength > limits.maxBytes) {
    throw new RangeError("decoded base64url size is outside the permitted range");
  }

  const padded =
    encoded.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - remainder) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

  if (encodeBase64Url(bytes) !== encoded) {
    throw new TypeError("value is not canonical base64url");
  }

  return bytes;
}
