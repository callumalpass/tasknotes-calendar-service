import { describe, expect, it } from "vitest";

import {
  OAuthTransactionSecretError,
  decryptOAuthTransactionProviderPkce,
  encryptOAuthTransactionProviderPkce,
  oauthTransactionProviderPkceEnvelopeFromRow,
  oauthTransactionProviderPkceEnvelopeToRow,
} from "../../../src/auth/oauth-transaction-secrets";
import type {
  OAuthTransactionProviderPkceEnvelope,
  OAuthTransactionSecretContext,
} from "../../../src/auth/oauth-transaction-secrets";
import { decodeBase64Url, encodeBase64Url } from "../../../src/crypto/base64url";
import type { RandomByteSource } from "../../../src/crypto/random";
import type { KeyEncryptionKeyring } from "../../../src/crypto/token-envelope";

const verifier = "A".repeat(43);
const context: OAuthTransactionSecretContext = {
  environment: "test",
  transactionId: "transaction-1",
  intent: "sign_in",
};
const key1 = Uint8Array.from({ length: 32 }, (_, index) => index);
const key2 = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
const keyring: KeyEncryptionKeyring = {
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
    if (value === undefined) throw new Error("test random sequence exhausted");
    return new Uint8Array(length).fill(value);
  }
}

function alterCanonical(encoded: string): string {
  const first = encoded[0];
  if (first === undefined) throw new Error("cannot alter an empty encoding");
  return `${first === "A" ? "B" : "A"}${encoded.slice(1)}`;
}

async function makeEnvelope(): Promise<OAuthTransactionProviderPkceEnvelope> {
  return encryptOAuthTransactionProviderPkce(
    verifier,
    context,
    keyring,
    new SequenceRandom(7, 8, 9),
  );
}

async function rawEncrypt(plaintext: Uint8Array, aad: Record<string, unknown>): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(7), "AES-GCM", false, [
    "encrypt",
  ]);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(12).fill(9),
      additionalData: new TextEncoder().encode(JSON.stringify(aad)),
      tagLength: 128,
    },
    key,
    Uint8Array.from(plaintext).buffer,
  );
  return encodeBase64Url(new Uint8Array(ciphertext));
}

function payloadAad(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    environment: context.environment,
    transactionId: context.transactionId,
    intent: context.intent,
    schemaVersion: 1,
    purpose: "payload",
    tokenKind: "provider_pkce",
    ...overrides,
  };
}

async function expectInvalid(value: unknown, suppliedContext = context): Promise<void> {
  await expect(
    decryptOAuthTransactionProviderPkce(value, suppliedContext, keyring),
  ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
}

describe("OAuth transaction provider PKCE secrets", () => {
  it("uses an injected random 32-byte DEK and separate 12-byte IVs", async () => {
    const envelope = await makeEnvelope();
    expect(Object.keys(envelope)).toEqual([
      "schemaVersion",
      "keyVersion",
      "dekIv",
      "wrappedDek",
      "payloadIv",
      "ciphertext",
    ]);
    expect(envelope).toMatchObject({ schemaVersion: 1, keyVersion: 1 });
    expect(decodeBase64Url(envelope.dekIv, { minBytes: 12, maxBytes: 12 })).toEqual(
      new Uint8Array(12).fill(8),
    );
    expect(decodeBase64Url(envelope.payloadIv, { minBytes: 12, maxBytes: 12 })).toEqual(
      new Uint8Array(12).fill(9),
    );
    await expect(decryptOAuthTransactionProviderPkce(envelope, context, keyring)).resolves.toBe(
      verifier,
    );
  });

  it("maps exactly to and from the six persisted provider_pkce columns", async () => {
    const envelope = await makeEnvelope();
    const row = oauthTransactionProviderPkceEnvelopeToRow(envelope);
    expect(row).toEqual({
      provider_pkce_schema_version: envelope.schemaVersion,
      provider_pkce_key_version: envelope.keyVersion,
      provider_pkce_dek_iv: envelope.dekIv,
      provider_pkce_wrapped_dek: envelope.wrappedDek,
      provider_pkce_payload_iv: envelope.payloadIv,
      provider_pkce_ciphertext: envelope.ciphertext,
    });
    expect(Object.keys(row)).toHaveLength(6);
    expect(oauthTransactionProviderPkceEnvelopeFromRow(row)).toEqual(envelope);
    expect(() =>
      oauthTransactionProviderPkceEnvelopeToRow({
        ...envelope,
        schemaVersion: 2,
      } as unknown as OAuthTransactionProviderPkceEnvelope),
    ).toThrow(OAuthTransactionSecretError);
    expect(() =>
      oauthTransactionProviderPkceEnvelopeFromRow({
        ...row,
        provider_pkce_schema_version: 2,
      }),
    ).toThrow(OAuthTransactionSecretError);
  });

  it.each(["dekIv", "wrappedDek", "payloadIv", "ciphertext"] as const)(
    "rejects tampering with %s",
    async (field) => {
      const envelope = await makeEnvelope();
      await expectInvalid({ ...envelope, [field]: alterCanonical(envelope[field]) });
    },
  );

  it.each([
    ["environment", "production"],
    ["transactionId", "transaction-2"],
    ["intent", "connect_calendar"],
  ] as const)("binds the %s AAD component", async (component, replacement) => {
    const envelope = await makeEnvelope();
    await expectInvalid(envelope, { ...context, [component]: replacement });
  });

  it.each([
    ["schemaVersion", 2],
    ["purpose", "dek"],
    ["tokenKind", "google_oauth"],
  ])("binds fixed payload AAD %s", async (component, replacement) => {
    const envelope = await makeEnvelope();
    const plaintext = new TextEncoder().encode(JSON.stringify({ verifier }));
    const ciphertext = await rawEncrypt(plaintext, payloadAad({ [component]: replacement }));
    await expectInvalid({ ...envelope, ciphertext });
  });

  it("binds the wrapped DEK to its key version and rejects unknown keys", async () => {
    const envelope = await makeEnvelope();
    await expectInvalid({ ...envelope, keyVersion: 2 });
    await expectInvalid({ ...envelope, keyVersion: 999 });
    await expectInvalid({ ...envelope, keyVersion: 0 });

    const sameKeyVersions: KeyEncryptionKeyring = {
      activeVersion: 2,
      keys: new Map([
        [1, key1],
        [2, key1],
      ]),
    };
    await expect(
      decryptOAuthTransactionProviderPkce({ ...envelope, keyVersion: 2 }, context, sameKeyVersions),
    ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
  });

  it("strictly validates the six-field envelope and encoded sizes", async () => {
    const envelope = await makeEnvelope();
    for (const invalid of [
      null,
      "plaintext-verifier",
      { ...envelope, extra: "field" },
      { ...envelope, schemaVersion: 2 },
      { ...envelope, dekIv: "A".repeat(1_000_000) },
      { ...envelope, wrappedDek: "A" },
      { ...envelope, payloadIv: "!".repeat(16) },
      { ...envelope, ciphertext: "A".repeat(100_000) },
    ]) {
      await expectInvalid(invalid);
    }
  });

  it("rejects authenticated malformed, expanded, and wrongly shaped payloads", async () => {
    const envelope = await makeEnvelope();
    const cases = [
      new TextEncoder().encode("{".padEnd(58, " ")),
      new TextEncoder().encode("null".padEnd(58, " ")),
      new TextEncoder().encode(JSON.stringify({ verifier, extra: true })),
      new TextEncoder().encode(JSON.stringify({ verifier: `${"A".repeat(42)}=` })),
      new TextEncoder().encode(JSON.stringify({ verifier: "\\".repeat(64) })),
      new Uint8Array(144).fill(65),
    ];
    for (const plaintext of cases) {
      const ciphertext = await rawEncrypt(plaintext, payloadAad());
      await expectInvalid({ ...envelope, ciphertext });
    }
  });

  it.each(["short", "A".repeat(42), "A".repeat(129), `${"A".repeat(42)}=`, `${"A".repeat(42)}é`])(
    "rejects a non-RFC7636 verifier without plaintext fallback: %s",
    async (invalid) => {
      await expect(
        encryptOAuthTransactionProviderPkce(invalid, context, keyring),
      ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
    },
  );

  it("rejects invalid contexts, keys, and random-source output", async () => {
    await expect(
      encryptOAuthTransactionProviderPkce(verifier, { ...context, environment: "" }, keyring),
    ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
    await expect(
      encryptOAuthTransactionProviderPkce(
        verifier,
        { ...context, intent: "reconnect" } as unknown as OAuthTransactionSecretContext,
        keyring,
      ),
    ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
    await expect(
      encryptOAuthTransactionProviderPkce(verifier, context, {
        activeVersion: 1,
        keys: new Map([[1, new Uint8Array(31)]]),
      }),
    ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
    await expect(
      encryptOAuthTransactionProviderPkce(verifier, context, keyring, {
        bytes: () => new Uint8Array(1),
      }),
    ).rejects.toBeInstanceOf(OAuthTransactionSecretError);
  });
});
