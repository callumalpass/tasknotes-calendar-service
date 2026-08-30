import { describe, expect, it } from "vitest";

import { constantTimeEqual, sha256 } from "../../../src/crypto/digest";
import { encodeBase64Url } from "../../../src/crypto/base64url";

describe("digest primitives", () => {
  it("computes SHA-256 using Web Crypto", async () => {
    const digest = await sha256(new TextEncoder().encode("abc"));
    expect(encodeBase64Url(digest)).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  });

  it("compares equal, different, and differently sized byte strings", () => {
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });
});
