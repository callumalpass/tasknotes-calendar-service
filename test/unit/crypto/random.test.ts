import { describe, expect, it } from "vitest";

import { randomBytes, webCryptoRandom } from "../../../src/crypto/random";
import type { RandomByteSource } from "../../../src/crypto/random";

describe("random bytes", () => {
  it("uses an injected deterministic source and copies its result", () => {
    const returned = new Uint8Array([1, 2, 3]);
    const source: RandomByteSource = { bytes: () => returned };
    const result = randomBytes(source, 3);
    returned[0] = 9;
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("rejects invalid requests and broken sources", () => {
    const source: RandomByteSource = { bytes: (length) => new Uint8Array(length) };
    for (const length of [0, -1, 1.5, 65_537, Number.NaN]) {
      expect(() => randomBytes(source, length)).toThrow(RangeError);
    }
    expect(() => randomBytes({ bytes: () => new Uint8Array(2) }, 3)).toThrow(Error);
  });

  it("provides Worker Web Crypto randomness", () => {
    const first = randomBytes(webCryptoRandom, 32);
    const second = randomBytes(webCryptoRandom, 32);
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toEqual(second);
    expect(() => webCryptoRandom.bytes(65_537)).toThrow(RangeError);
  });
});
