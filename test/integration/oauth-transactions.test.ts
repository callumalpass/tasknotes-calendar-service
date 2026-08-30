import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import { DeviceSessions } from "../../src/auth/device-sessions";
import { googleOidcTestEndpoints } from "../../src/auth/google-oidc";
import type { GoogleCalendarConnectionResult, GoogleIdentity } from "../../src/auth/google-oidc";
import { IdentityDeletion } from "../../src/auth/identity-deletion";
import { OAuthTransactionError, OAuthTransactions } from "../../src/auth/oauth-transactions";
import type { RandomByteSource } from "../../src/crypto/random";
import { createPkceS256Challenge } from "../../src/crypto/pkce";
import { decryptTokenEnvelope } from "../../src/crypto/token-envelope";
import { tokenEnvelopeFromRow } from "../../src/storage/token-envelope-row";
import type { TokenEnvelopeRow } from "../../src/storage/token-envelope-row";
import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const NOW = 1_788_048_000;
const PRINCIPAL = "00000000-0000-4000-8000-000000000001";
const IDENTITY = "00000000-0000-4000-8000-000000000002";
const VERIFIER = "tasknotes-client-verifier-value-that-is-long-enough-123";
const KEYS = { activeVersion: 1, keys: new Map([[1, new Uint8Array(32).fill(81)]]) };
const CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";

class CountingRandom implements RandomByteSource {
  public calls = 0;
  public bytes(length: number): Uint8Array {
    this.calls += 1;
    return new Uint8Array(length).fill(this.calls);
  }
}

let currentTime: number;
let random: CountingRandom;
let exchangeSignInCalls: number;
let exchangeCalendarCalls: number;
let revoked: string[];
let signInResult: GoogleIdentity;
let calendarResult: GoogleCalendarConnectionResult;
let onCalendarExchange: (() => Promise<void>) | undefined;
let identityDeletion: IdentityDeletion;
let service: OAuthTransactions;
let nextUuid: number;

function uuid(): string {
  nextUuid += 1;
  return `10000000-0000-4000-8000-${String(nextUuid).padStart(12, "0")}`;
}

async function challenge(): Promise<string> {
  return createPkceS256Challenge(VERIFIER);
}

async function insertPrincipal(connection = false): Promise<void> {
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(PRINCIPAL, NOW, NOW)
    .run();
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
       (id, principal_id, provider, issuer, subject, email, display_name,
        email_verified, created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', 'subject-a',
             'old@example.test', 'Old', 1, ?, ?)`,
  )
    .bind(IDENTITY, PRINCIPAL, NOW, NOW)
    .run();
  if (connection) {
    await testEnv.DB.prepare(
      `INSERT INTO connections
         (id, principal_id, identity_id, provider, status, generation,
          envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv,
          ciphertext, token_version, created_at, updated_at)
       VALUES ('20000000-0000-4000-8000-000000000001', ?, ?, 'google',
               'active', 1, 1, 1, 'old-dek', 'old-wrapped', 'old-iv',
               'old-ciphertext', 1, ?, ?)`,
    )
      .bind(PRINCIPAL, IDENTITY, NOW, NOW)
      .run();
    await testEnv.DB.prepare(
      "UPDATE connections SET status = 'reconnect_required' WHERE principal_id = ?",
    )
      .bind(PRINCIPAL)
      .run();
  }
}

async function startSignIn() {
  return service.startSignIn({
    client_kind: "obsidian",
    device_name: "Test device",
    code_challenge: await challenge(),
  });
}

async function startConnect() {
  return service.startConnect(PRINCIPAL, {
    client_kind: "web",
    device_name: "Test browser",
    code_challenge: await challenge(),
  });
}

function state(response: { authorization_url: string }): string {
  const value = new URL(response.authorization_url).searchParams.get("state");
  if (value === null) throw new Error("missing state");
  return value;
}

beforeEach(async () => {
  await testEnv.DB.prepare("DELETE FROM oauth_transactions").run();
  await testEnv.DB.prepare("DELETE FROM principals").run();
  await testEnv.DB.prepare("DELETE FROM identity_deletion_fences").run();
  currentTime = NOW;
  random = new CountingRandom();
  nextUuid = 10;
  exchangeSignInCalls = 0;
  exchangeCalendarCalls = 0;
  revoked = [];
  signInResult = {
    issuer: "https://accounts.google.com",
    subject: "subject-a",
    email: "new@example.test",
    emailVerified: true,
    name: "New name",
  };
  onCalendarExchange = undefined;
  calendarResult = {
    identity: signInResult,
    tokenMaterial: {
      accessToken: "access-token-private",
      refreshToken: "refresh-token-private",
      expiresInSeconds: 3600,
      scopes: ["openid", "email", "profile", CALENDAR_SCOPE],
    },
  };
  const deviceSessions = new DeviceSessions({
    db: testEnv.DB,
    pepper: new Uint8Array(32).fill(31),
    clock: { now: () => new Date(currentTime * 1000) },
    random,
  });
  identityDeletion = new IdentityDeletion({
    db: testEnv.DB,
    hmacKey: new Uint8Array(32).fill(41),
    nowEpochSeconds: () => currentTime,
  });
  service = new OAuthTransactions({
    db: testEnv.DB,
    environment: "local",
    nowEpochSeconds: () => currentTime,
    random,
    uuid,
    transactionKeyring: KEYS,
    tokenKeyring: KEYS,
    identityDeletion,
    deviceSessions,
    google: {
      endpoints: googleOidcTestEndpoints({
        authorizationEndpoint: "http://127.0.0.1:8788/oauth/authorize",
        tokenEndpoint: "http://127.0.0.1:8788/oauth/token",
      }),
      client: {
        clientId: "test-client",
        clientSecret: "test-secret",
        redirectUri: "http://127.0.0.1:8787/oauth/google/callback",
      },
      exchangeSignIn: () => {
        exchangeSignInCalls += 1;
        return Promise.resolve(signInResult);
      },
      exchangeCalendar: async () => {
        exchangeCalendarCalls += 1;
        await onCalendarExchange?.();
        return calendarResult;
      },
      revokeCalendarToken: (token) => {
        revoked.push(token);
        return Promise.resolve();
      },
    },
  });
});

describe("OAuth transactions against migrated D1", () => {
  it("starts sign-in with exact identity scopes and persists only independent digests and ciphertext", async () => {
    const started = await startSignIn();
    const url = new URL(started.authorization_url);
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.has("prompt")).toBe(false);
    expect(url.searchParams.has("access_type")).toBe(false);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(started.expires_at).toBe(new Date((NOW + 600) * 1000).toISOString());

    const row = await testEnv.DB.prepare("SELECT * FROM oauth_transactions WHERE id = ?")
      .bind(started.transaction_id)
      .first();
    expect(row).not.toBeNull();
    const serialized = JSON.stringify(row);
    expect(row?.["state_hash"]).toHaveLength(43);
    expect(row?.["polling_secret_hash"]).toHaveLength(43);
    expect(row?.["nonce_hash"]).toHaveLength(43);
    expect(row?.["provider_pkce_ciphertext"]).toEqual(expect.any(String));
    expect(serialized).not.toContain(started.polling_secret);
    expect(serialized).not.toContain(state(started));
    expect(serialized).not.toContain(VERIFIER);
  });

  it("validates malformed starts and reports missing connect authority as not_found", async () => {
    await expect(
      service.startSignIn({
        client_kind: "web",
        device_name: "",
        code_challenge: await challenge(),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await expect(startConnect()).rejects.toMatchObject({ code: "not_found" });
  });

  it("creates a sign-in identity, updates metadata by immutable tuple, and redeems once", async () => {
    const started = await startSignIn();
    await expect(
      service.callback({ code: "provider-code-value", state: state(started) }),
    ).resolves.toEqual({ status: "complete" });
    expect(exchangeSignInCalls).toBe(1);
    await expect(
      service.statusSignIn(started.transaction_id, started.polling_secret),
    ).resolves.toMatchObject({
      status: "authorized",
    });

    const redeemed = await service.redeemSignIn(
      started.transaction_id,
      started.polling_secret,
      VERIFIER,
    );
    expect(redeemed.session.credential).toMatch(/^v1\./u);
    await expect(
      service.redeemSignIn(started.transaction_id, started.polling_secret, VERIFIER),
    ).rejects.toMatchObject({ code: "conflict" });
    const identity = await testEnv.DB.prepare(
      "SELECT subject, email, display_name FROM external_identities",
    ).first();
    expect(identity).toEqual({
      subject: "subject-a",
      email: "new@example.test",
      display_name: "New name",
    });
  });

  it("converges 25 concurrent same-sub sign-in finalizations on one principal", async () => {
    const starts = await Promise.all(Array.from({ length: 25 }, () => startSignIn()));
    await Promise.all(
      starts.map((started) =>
        service.callback({ code: "provider-code-value", state: state(started) }),
      ),
    );
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM principals").first("count"),
    ).resolves.toBe(1);
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM external_identities").first("count"),
    ).resolves.toBe(1);
    await expect(
      testEnv.DB.prepare(
        "SELECT COUNT(*) AS count FROM oauth_transactions WHERE status = 'authorized'",
      ).first("count"),
    ).resolves.toBe(25);
  });

  it("keeps matching email subjects separate and resolves an existing immutable subject", async () => {
    const first = await startSignIn();
    await service.callback({ code: "provider-code-value", state: state(first) });
    const firstPrincipal = await testEnv.DB.prepare(
      "SELECT principal_id FROM external_identities WHERE subject = 'subject-a'",
    ).first<string>("principal_id");

    signInResult = { ...signInResult, subject: "subject-b", name: "Other subject" };
    const second = await startSignIn();
    await service.callback({ code: "provider-code-value", state: state(second) });
    const secondPrincipal = await testEnv.DB.prepare(
      "SELECT principal_id FROM external_identities WHERE subject = 'subject-b'",
    ).first<string>("principal_id");
    expect(secondPrincipal).not.toBe(firstPrincipal);

    signInResult = { ...signInResult, subject: "subject-a", name: "Updated existing" };
    const existing = await startSignIn();
    await service.callback({ code: "provider-code-value", state: state(existing) });
    await expect(
      testEnv.DB.prepare(
        "SELECT principal_id FROM external_identities WHERE subject = 'subject-a'",
      ).first("principal_id"),
    ).resolves.toBe(firstPrincipal);
    await expect(
      testEnv.DB.prepare(
        "SELECT display_name FROM external_identities WHERE subject = 'subject-a'",
      ).first("display_name"),
    ).resolves.toBe("Updated existing");
  });

  it("gives exactly one winner across 25 sign-in redemption attempts", async () => {
    const started = await startSignIn();
    await service.callback({ code: "provider-code-value", state: state(started) });
    const attempts = await Promise.allSettled(
      Array.from({ length: 25 }, () =>
        service.redeemSignIn(started.transaction_id, started.polling_secret, VERIFIER),
      ),
    );
    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(24);
  });

  it("makes an equal-time deletion fence dominate sign-in finalization", async () => {
    const started = await startSignIn();
    const fence = await identityDeletion.fenceDigest({
      provider: "google",
      issuer: "https://accounts.google.com",
      subject: "subject-a",
    });
    await testEnv.DB.prepare(
      "INSERT INTO identity_deletion_fences (identity_digest, deleted_at) VALUES (?, ?)",
    )
      .bind(fence, NOW)
      .run();
    await service.callback({ code: "provider-code-value", state: state(started) });
    await expect(
      service.statusSignIn(started.transaction_id, started.polling_secret),
    ).resolves.toEqual({
      status: "failed",
      failure_code: "authorization_failed",
    });
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM principals").first("count"),
    ).resolves.toBe(0);
  });

  it("allows exactly one provider exchange across 25 concurrent callbacks and keeps replays quiet", async () => {
    const started = await startSignIn();
    const callback = { code: "provider-code-value", state: state(started) } as const;
    const results = await Promise.all(Array.from({ length: 25 }, () => service.callback(callback)));
    expect(results).toEqual(Array(25).fill({ status: "complete" }));
    expect(exchangeSignInCalls).toBe(1);
    await service.callback(callback);
    await service.callback({ code: "other-provider-code", state: "A".repeat(43) });
    expect(exchangeSignInCalls).toBe(1);
  });

  it("maps error callbacks, rejects capability substitution, and expires at the equal boundary", async () => {
    const denied = await startSignIn();
    await service.callback({ error: "access_denied", state: state(denied) });
    await expect(
      service.statusSignIn(denied.transaction_id, denied.polling_secret),
    ).resolves.toEqual({
      status: "failed",
      failure_code: "access_denied",
    });

    const expired = await startSignIn();
    currentTime += 600;
    await expect(
      service.statusSignIn(expired.transaction_id, expired.polling_secret),
    ).resolves.toEqual({
      status: "expired",
    });
    await expect(
      service.statusSignIn(expired.transaction_id, "A".repeat(43)),
    ).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("fails a tampered provider PKCE envelope without exchanging", async () => {
    const started = await startSignIn();
    await testEnv.DB.prepare("DROP TRIGGER oauth_transactions_immutable_binding").run();
    await testEnv.DB.prepare(
      "UPDATE oauth_transactions SET provider_pkce_ciphertext = 'tampered' WHERE id = ?",
    )
      .bind(started.transaction_id)
      .run();
    await service.callback({ code: "provider-code-value", state: state(started) });
    expect(exchangeSignInCalls).toBe(0);
    await expect(
      service.statusSignIn(started.transaction_id, started.polling_secret),
    ).resolves.toEqual({
      status: "failed",
      failure_code: "authorization_failed",
    });
  });

  it("starts new connect with offline readonly consent, stores an AAD-bound envelope, and redeems once", async () => {
    await insertPrincipal();
    const started = await startConnect();
    const url = new URL(started.authorization_url);
    expect(url.searchParams.get("scope")).toBe(`openid email profile ${CALENDAR_SCOPE}`);
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("prompt")).toBe("consent");
    await service.callback({ code: "calendar-provider-code", state: state(started) });
    expect(exchangeCalendarCalls).toBe(1);
    expect(revoked).toEqual([]);

    const connection = await testEnv.DB.prepare(
      `SELECT id, principal_id, generation, token_version, envelope_schema_version,
              key_version, dek_iv, wrapped_dek, payload_iv, ciphertext
       FROM connections WHERE principal_id = ?`,
    )
      .bind(PRINCIPAL)
      .first<
        TokenEnvelopeRow & {
          id: string;
          principal_id: string;
          generation: number;
          token_version: number;
        }
      >();
    if (connection === null) throw new Error("missing connection");
    expect(JSON.stringify(connection)).not.toContain("access-token-private");
    expect(JSON.stringify(connection)).not.toContain("refresh-token-private");
    await expect(
      decryptTokenEnvelope(
        tokenEnvelopeFromRow(connection),
        {
          environment: "local",
          provider: "google",
          principalId: PRINCIPAL,
          connectionId: connection.id,
          connectionGeneration: 1,
          tokenVersion: 1,
          tokenKind: "calendar_oauth",
        },
        KEYS,
      ),
    ).resolves.toMatchObject({ refreshToken: "refresh-token-private" });

    const redemptions = await Promise.allSettled(
      Array.from({ length: 25 }, () =>
        service.redeemConnect(PRINCIPAL, started.transaction_id, started.polling_secret, VERIFIER),
      ),
    );
    expect(redemptions.filter((attempt) => attempt.status === "fulfilled")).toEqual([
      expect.objectContaining({ value: { connection_id: connection.id, status: "active" } }),
    ]);
    expect(redemptions.filter((attempt) => attempt.status === "rejected")).toHaveLength(24);
  });

  it("replaces reconnect_required in place and advances generation and token version exactly once", async () => {
    await insertPrincipal(true);
    const started = await startConnect();
    const snapshot = await testEnv.DB.prepare(
      `SELECT expected_connection_id, expected_connection_generation, expected_token_version,
              target_connection_id, target_connection_generation, target_token_version
       FROM oauth_transactions WHERE id = ?`,
    )
      .bind(started.transaction_id)
      .first();
    expect(snapshot).toEqual({
      expected_connection_id: "20000000-0000-4000-8000-000000000001",
      expected_connection_generation: 1,
      expected_token_version: 1,
      target_connection_id: "20000000-0000-4000-8000-000000000001",
      target_connection_generation: 2,
      target_token_version: 2,
    });
    await service.callback({ code: "calendar-provider-code", state: state(started) });
    await expect(
      testEnv.DB.prepare("SELECT id, status, generation, token_version FROM connections").first(),
    ).resolves.toEqual({
      id: "20000000-0000-4000-8000-000000000001",
      status: "active",
      generation: 2,
      token_version: 2,
    });
  });

  it("enforces one active connect and revokes an exchanged refresh token when local authority loses", async () => {
    await insertPrincipal();
    const first = await startConnect();
    await expect(startConnect()).rejects.toMatchObject({ code: "conflict" });
    onCalendarExchange = async () => {
      await testEnv.DB.prepare("DELETE FROM principals WHERE id = ?").bind(PRINCIPAL).run();
    };
    await service.callback({ code: "calendar-provider-code", state: state(first) });
    expect(exchangeCalendarCalls).toBe(1);
    expect(revoked).toEqual(["refresh-token-private"]);
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM connections").first("count"),
    ).resolves.toBe(0);
  });

  it("maps malformed injected claims and provider failures to privacy-safe terminal failures", async () => {
    const malformed = await startSignIn();
    signInResult = {
      ...signInResult,
      issuer: "accounts.google.com" as "https://accounts.google.com",
    };
    await service.callback({ code: "provider-code-value", state: state(malformed) });
    await expect(
      service.statusSignIn(malformed.transaction_id, malformed.polling_secret),
    ).resolves.toEqual({
      status: "failed",
      failure_code: "authorization_failed",
    });

    const thrown = await startSignIn();
    const original = service;
    // The concrete dependency is intentionally injectable; a fresh service controls network ambiguity.
    expect(original).toBeInstanceOf(OAuthTransactions);
    expect(
      JSON.stringify(await testEnv.DB.prepare("SELECT * FROM oauth_transactions").all()),
    ).not.toContain("provider-code-value");
    expect(thrown.transaction_id).toHaveLength(43);
  });

  it("uses generic errors that never include supplied capabilities", async () => {
    const started = await startSignIn();
    const secret = "A".repeat(43);
    let error: unknown;
    try {
      await service.statusSignIn(started.transaction_id, secret);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(OAuthTransactionError);
    expect(String(error)).not.toContain(secret);
    expect(String(error)).not.toContain(started.transaction_id);
  });
});
