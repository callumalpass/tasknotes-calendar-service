import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { constantTimeEqual, sha256 } from "./digest";

const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;

export function isValidPkceVerifier(verifier: string): boolean {
  return PKCE_VERIFIER_PATTERN.test(verifier);
}

export async function createPkceS256Challenge(verifier: string): Promise<string> {
  if (!isValidPkceVerifier(verifier)) {
    throw new TypeError("PKCE verifier must contain 43 to 128 RFC 7636 unreserved characters");
  }

  return encodeBase64Url(await sha256(new TextEncoder().encode(verifier)));
}

export async function verifyPkceS256Challenge(
  verifier: string,
  expectedChallenge: string,
): Promise<boolean> {
  if (!isValidPkceVerifier(verifier)) {
    return false;
  }

  let expectedBytes: Uint8Array;
  try {
    expectedBytes = decodeBase64Url(expectedChallenge, { minBytes: 32, maxBytes: 32 });
  } catch {
    return false;
  }

  const actualBytes = await sha256(new TextEncoder().encode(verifier));
  return constantTimeEqual(actualBytes, expectedBytes);
}
