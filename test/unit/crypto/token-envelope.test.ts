import { describe, expect, it } from "vitest";

import { decodeBase64Url, encodeBase64Url } from "../../../src/crypto/base64url";
import {
  TokenEnvelopeError,
  decryptTokenEnvelope,
  encryptTokenEnvelope,
  rewrapTokenEnvelope,
} from "../../../src/crypto/token-envelope";
import type {
  KeyEncryptionKeyring,
  TokenEnvelope,
  TokenEnvelopeContext,
  TokenPayload,
} from "../../../src/crypto/token-envelope";
import type { RandomByteSource } from "../../../src/crypto/random";

const payload: TokenPayload = {
  accessToken: "access-secret",
  refreshToken: "refresh-secret",
  expiresAtEpochSeconds: 2_000_000_000,
  scopes: ["openid", "https://www.googleapis.com/auth/calendar.readonly"],
};
const context: TokenEnvelopeContext = {
  environment: "test",
  provider: "google",
  principalId: "principal-1",
  connectionId: "connection-1",
  connectionGeneration: 3,
  tokenVersion: 7,
  tokenKind: "google_oauth",
};
const key1 = Uint8Array.from({ length: 32 }, (_, index) => index);
const key2 = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
const keyring1: KeyEncryptionKeyring = {
  activeVersion: 1,
  keys: new Map([
    [1, key1],
    [2, key2],
  ]),
};

class SequenceRandom implements RandomByteSource {
  readonly #values: number[];

  public constructor(...values: number[]) {
    this.#values = values;
  }

  public bytes(length: number): Uint8Array {
    const value = this.#values.shift();
    if (value === undefined) {
      throw new Error("test random sequence exhausted");
    }
    return new Uint8Array(length).fill(value);
  }
}

function alterCanonical(encoded: string): string {
  const first = encoded[0];
  if (first === undefined) {
    throw new Error("cannot alter an empty encoding");
  }
  return `${first === "A" ? "B" : "A"}${encoded.slice(1)}`;
}

async function makeEnvelope(): Promise<TokenEnvelope> {
  return encryptTokenEnvelope(payload, context, keyring1, new SequenceRandom(7, 8, 9));
}

async function rawAesEncrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(keyBytes).buffer,
    "AES-GCM",
    false,
    ["encrypt"],
  );
  return new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: Uint8Array.from(iv).buffer,
        additionalData: Uint8Array.from(aad).buffer,
        tagLength: 128,
      },
      key,
      Uint8Array.from(plaintext).buffer,
    ),
  );
}

describe("token envelopes", () => {
  it("encrypts with an injected random DEK and IVs and decrypts the typed payload", async () => {
    const first = await makeEnvelope();
    const second = await makeEnvelope();

    expect(first).toEqual(second);
    expect(first).toMatchObject({ schemaVersion: 1, keyVersion: 1 });
    expect(decodeBase64Url(first.dekIv, { minBytes: 12, maxBytes: 12 })).toEqual(
      new Uint8Array(12).fill(8),
    );
    expect(decodeBase64Url(first.payloadIv, { minBytes: 12, maxBytes: 12 })).toEqual(
      new Uint8Array(12).fill(9),
    );
    await expect(decryptTokenEnvelope(first, context, keyring1)).resolves.toEqual(payload);
  });

  it.each(["dekIv", "wrappedDek", "payloadIv", "ciphertext"] as const)(
    "rejects tampering with persisted %s",
    async (field) => {
      const envelope = await makeEnvelope();
      const tampered = { ...envelope, [field]: alterCanonical(envelope[field]) };
      await expect(decryptTokenEnvelope(tampered, context, keyring1)).rejects.toBeInstanceOf(
        TokenEnvelopeError,
      );
    },
  );

  it("rejects tampered schema and key versions, including unknown versions", async () => {
    const envelope = await makeEnvelope();
    for (const tampered of [
      { ...envelope, schemaVersion: 2 },
      { ...envelope, keyVersion: 2 },
      { ...envelope, keyVersion: 999 },
      { ...envelope, keyVersion: 0 },
    ]) {
      await expect(decryptTokenEnvelope(tampered, context, keyring1)).rejects.toBeInstanceOf(
        TokenEnvelopeError,
      );
    }
  });

  it.each([
    ["environment", "production"],
    ["provider", "microsoft"],
    ["principalId", "principal-2"],
    ["connectionId", "connection-2"],
    ["connectionGeneration", 4],
    ["tokenVersion", 8],
    ["tokenKind", "provider_pkce"],
  ] as const)("binds the %s AAD component", async (component, replacement) => {
    const envelope = await makeEnvelope();
    const wrongContext = { ...context, [component]: replacement } as TokenEnvelopeContext;
    await expect(decryptTokenEnvelope(envelope, wrongContext, keyring1)).rejects.toBeInstanceOf(
      TokenEnvelopeError,
    );
  });

  it("strictly validates envelope shape and encoded field limits", async () => {
    const envelope = await makeEnvelope();
    await expect(
      decryptTokenEnvelope({ ...envelope, extra: "field" }, context, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      decryptTokenEnvelope({ ...envelope, dekIv: "A".repeat(1_000_000) }, context, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      decryptTokenEnvelope({ ...envelope, ciphertext: "A".repeat(100_000) }, context, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(decryptTokenEnvelope(null, context, keyring1)).rejects.toBeInstanceOf(
      TokenEnvelopeError,
    );
  });

  it("runtime-validates authenticated decrypted payloads", async () => {
    const envelope = await makeEnvelope();
    const invalidPayload = new TextEncoder().encode(
      JSON.stringify({ ...payload, expiresAtEpochSeconds: "never" }),
    );
    const aad = new TextEncoder().encode(
      JSON.stringify({
        environment: context.environment,
        provider: context.provider,
        principalId: context.principalId,
        connectionId: context.connectionId,
        connectionGeneration: context.connectionGeneration,
        tokenVersion: context.tokenVersion,
        tokenKind: context.tokenKind,
        schemaVersion: 1,
        purpose: "payload",
      }),
    );
    const ciphertext = await rawAesEncrypt(
      new Uint8Array(32).fill(7),
      new Uint8Array(12).fill(9),
      invalidPayload,
      aad,
    );

    await expect(
      decryptTokenEnvelope(
        { ...envelope, ciphertext: encodeBase64Url(ciphertext) },
        context,
        keyring1,
      ),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
  });

  it("rejects invalid payloads, contexts, key sizes, and random sources on encryption", async () => {
    await expect(
      encryptTokenEnvelope({ ...payload, accessToken: "x".repeat(16_385) }, context, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      encryptTokenEnvelope(payload, { ...context, principalId: "" }, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      encryptTokenEnvelope(payload, { ...context, connectionGeneration: 0 }, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      encryptTokenEnvelope(payload, { ...context, tokenVersion: 0 }, keyring1),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      encryptTokenEnvelope(payload, context, {
        activeVersion: 1,
        keys: new Map([[1, new Uint8Array(31)]]),
      }),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
    await expect(
      encryptTokenEnvelope(payload, context, keyring1, { bytes: () => new Uint8Array(1) }),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
  });

  it("rejects escape-expanded payloads that cannot produce a decryptable envelope", async () => {
    await expect(
      encryptTokenEnvelope(
        {
          ...payload,
          accessToken: String.fromCharCode(0).repeat(16_000),
          refreshToken: String.fromCharCode(0).repeat(16_000),
        },
        context,
        keyring1,
      ),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
  });

  it("rewraps only the DEK to a newer active KEK and remains decryptable", async () => {
    const envelope = await makeEnvelope();
    const rotated: KeyEncryptionKeyring = {
      activeVersion: 2,
      keys: keyring1.keys,
    };
    const rewrapped = await rewrapTokenEnvelope(envelope, context, rotated, new SequenceRandom(10));

    expect(rewrapped.keyVersion).toBe(2);
    expect(rewrapped.dekIv).not.toBe(envelope.dekIv);
    expect(rewrapped.wrappedDek).not.toBe(envelope.wrappedDek);
    expect(rewrapped.payloadIv).toBe(envelope.payloadIv);
    expect(rewrapped.ciphertext).toBe(envelope.ciphertext);
    await expect(decryptTokenEnvelope(rewrapped, context, rotated)).resolves.toEqual(payload);
    await expect(
      decryptTokenEnvelope(rewrapped, context, {
        activeVersion: 2,
        keys: new Map([[1, key1]]),
      }),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
  });

  it("refuses same-version rewrap and key-version downgrade", async () => {
    const envelope = await makeEnvelope();
    await expect(rewrapTokenEnvelope(envelope, context, keyring1)).rejects.toBeInstanceOf(
      TokenEnvelopeError,
    );

    const rotated: KeyEncryptionKeyring = { activeVersion: 2, keys: keyring1.keys };
    const rewrapped = await rewrapTokenEnvelope(envelope, context, rotated, new SequenceRandom(10));
    await expect(
      rewrapTokenEnvelope(rewrapped, context, { activeVersion: 1, keys: keyring1.keys }),
    ).rejects.toBeInstanceOf(TokenEnvelopeError);
  });
});
