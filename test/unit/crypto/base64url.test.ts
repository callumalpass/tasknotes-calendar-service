import { describe, expect, it } from "vitest";

import { decodeBase64Url, encodeBase64Url } from "../../../src/crypto/base64url";

describe("base64url", () => {
  it.each([
    [new Uint8Array(), ""],
    [new TextEncoder().encode("f"), "Zg"],
    [new TextEncoder().encode("fo"), "Zm8"],
    [new TextEncoder().encode("foo"), "Zm9v"],
    [new Uint8Array([251, 255, 239]), "-__v"],
  ])("round trips canonical vectors", (bytes, encoded) => {
    expect(encodeBase64Url(bytes)).toBe(encoded);
    expect(decodeBase64Url(encoded, { maxBytes: bytes.length })).toEqual(bytes);
  });

  it.each(["Zg=", "Zg==", "Zm+8", "Zm/8", "Z g", "A", "AB", "é"])(
    "rejects non-canonical input %s",
    (encoded) => {
      expect(() => decodeBase64Url(encoded, { maxBytes: 100 })).toThrow(TypeError);
    },
  );

  it("enforces decoded limits before decoding", () => {
    expect(() => decodeBase64Url("Zm9v", { minBytes: 4, maxBytes: 10 })).toThrow(RangeError);
    expect(() => decodeBase64Url("Zm9v", { maxBytes: 2 })).toThrow(RangeError);
    expect(() => decodeBase64Url("A".repeat(1_000_000), { maxBytes: 16 })).toThrow();
  });

  it("rejects invalid limit declarations", () => {
    expect(() => decodeBase64Url("", { maxBytes: -1 })).toThrow(TypeError);
    expect(() => decodeBase64Url("", { minBytes: 2, maxBytes: 1 })).toThrow(TypeError);
    expect(() => decodeBase64Url("", { maxBytes: 1.5 })).toThrow(TypeError);
  });
});
