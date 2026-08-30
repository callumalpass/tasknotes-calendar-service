import { describe, expect, it } from "vitest";

import {
  createPkceS256Challenge,
  isValidPkceVerifier,
  verifyPkceS256Challenge,
} from "../../../src/crypto/pkce";

const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("PKCE S256", () => {
  it("matches the RFC 7636 example", async () => {
    await expect(createPkceS256Challenge(RFC_VERIFIER)).resolves.toBe(RFC_CHALLENGE);
    await expect(verifyPkceS256Challenge(RFC_VERIFIER, RFC_CHALLENGE)).resolves.toBe(true);
  });

  it("accepts only the RFC verifier grammar and bounds", async () => {
    expect(isValidPkceVerifier("A".repeat(43))).toBe(true);
    expect(isValidPkceVerifier("A".repeat(128))).toBe(true);
    expect(isValidPkceVerifier("aA0-._~".repeat(7))).toBe(true);
    for (const verifier of [
      "A".repeat(42),
      "A".repeat(129),
      `${"A".repeat(42)}!`,
      `${"A".repeat(42)}é`,
    ]) {
      expect(isValidPkceVerifier(verifier)).toBe(false);
      await expect(createPkceS256Challenge(verifier)).rejects.toThrow(TypeError);
    }
  });

  it.each([
    ["wrong", RFC_CHALLENGE],
    [RFC_VERIFIER, `${RFC_CHALLENGE.slice(0, -1)}A`],
    [RFC_VERIFIER, `${RFC_CHALLENGE}=`],
    [RFC_VERIFIER, "A".repeat(1_000_000)],
  ])("fails closed for an invalid verifier or challenge", async (verifier, challenge) => {
    await expect(verifyPkceS256Challenge(verifier, challenge)).resolves.toBe(false);
  });
});
