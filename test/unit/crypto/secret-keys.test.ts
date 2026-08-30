import { describe, expect, it } from "vitest";

import { encodeBase64Url } from "../../../src/crypto/base64url";
import {
  SecretConfigurationError,
  decodeSecretKey,
  eventIdKeyFromEnvironment,
  tokenKeyringFromEnvironment,
} from "../../../src/crypto/secret-keys";

const KEY = Uint8Array.from({ length: 32 }, (_, index) => index);

describe("secret key configuration", () => {
  it("decodes a canonical exact-length key", () => {
    expect(decodeSecretKey("TEST_KEY", encodeBase64Url(KEY))).toEqual(KEY);
  });

  it.each(["", "not+base64url", `${encodeBase64Url(KEY)}=`, encodeBase64Url(KEY.subarray(1))])(
    "rejects malformed secret %j without including its value in the error",
    (encoded) => {
      expect(() => decodeSecretKey("TEST_KEY", encoded)).toThrow(SecretConfigurationError);
      try {
        decodeSecretKey("TEST_KEY", encoded);
      } catch (error) {
        expect(String(error)).toContain("TEST_KEY");
        if (encoded.length > 0) {
          expect(String(error)).not.toContain(encoded);
        }
      }
    },
  );

  it("parses the dedicated non-rotating event ID key exactly once", () => {
    expect(eventIdKeyFromEnvironment({ EVENT_ID_KEY_V1: encodeBase64Url(KEY) })).toEqual(KEY);
    expect(() =>
      eventIdKeyFromEnvironment({ EVENT_ID_KEY_V1: encodeBase64Url(KEY.subarray(1)) }),
    ).toThrow(SecretConfigurationError);
  });

  it("constructs the initial versioned token keyring", () => {
    const keyring = tokenKeyringFromEnvironment({ TOKEN_KEK_V1: encodeBase64Url(KEY) });

    expect(keyring.activeVersion).toBe(1);
    expect(keyring.keys).toEqual(new Map([[1, KEY]]));
  });
});
