import { decodeBase64Url } from "./base64url";
import type { KeyEncryptionKeyring } from "./token-envelope";

const KEY_BYTES = 32;

export class SecretConfigurationError extends Error {
  public constructor(name: string) {
    super(`${name} is not a canonical 32-byte base64url secret`);
    this.name = "SecretConfigurationError";
  }
}

export function decodeSecretKey(name: string, encoded: string): Uint8Array {
  try {
    return decodeBase64Url(encoded, { minBytes: KEY_BYTES, maxBytes: KEY_BYTES });
  } catch {
    throw new SecretConfigurationError(name);
  }
}

export function eventIdKeyFromEnvironment(environment: {
  readonly EVENT_ID_KEY_V1: string;
}): Uint8Array {
  return decodeSecretKey("EVENT_ID_KEY_V1", environment.EVENT_ID_KEY_V1);
}

export function tokenKeyringFromEnvironment(environment: {
  readonly TOKEN_KEK_V1: string;
}): KeyEncryptionKeyring {
  return {
    activeVersion: 1,
    keys: new Map([[1, decodeSecretKey("TOKEN_KEK_V1", environment.TOKEN_KEK_V1)]]),
  };
}
