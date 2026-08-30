import { decodeBase64Url } from "../crypto/base64url";

const VERSION = "v1";
const SESSION_ID_BYTES = 16;
const SECRET_BYTES = 32;

export interface ParsedServiceCredential {
  readonly sessionId: Uint8Array;
  readonly secret: Uint8Array;
}

export function parseServiceCredential(value: unknown): ParsedServiceCredential | null {
  if (typeof value !== "string" || value.length > 80) return null;
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) return null;
  try {
    return {
      sessionId: decodeBase64Url(parts[1] ?? "", {
        minBytes: SESSION_ID_BYTES,
        maxBytes: SESSION_ID_BYTES,
      }),
      secret: decodeBase64Url(parts[2] ?? "", {
        minBytes: SECRET_BYTES,
        maxBytes: SECRET_BYTES,
      }),
    };
  } catch {
    return null;
  }
}

export function isServiceCredential(value: unknown): value is string {
  return parseServiceCredential(value) !== null;
}
