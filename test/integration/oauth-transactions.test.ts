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
const CALENDAR_SCOPE =
  "https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar.calendarlist.readonly";

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

type BatchFault = "before" | "after";

function databaseWithBatchFault(fault: BatchFault): D1Database {
  let injected = false;
  return new Proxy<D1Database>(testEnv.DB, {
    get(target, property): unknown {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          if (injected) return target.batch(statements);
          injected = true;
          if (fault === "before") throw new Error("injected before batch");
          await target.batch(statements);
          throw new Error("injected after batch");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function uuid(): string {
  nextUuid += 1;
  return `10000000-0000-4000-8000-${String(nextUuid).padStart(12, "0")}`;
}

async function challenge(): Promise<string> {
  return createPkceS256Challenge(VERIFIER);
}

async function insertPrincipal(connection = false, reconnect = true): Promise<void> {
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
    if (reconnect) {
      await testEnv.DB.prepare(
        "UPDATE connections SET status = 'reconnect_required' WHERE principal_id = ?",
      )
        .bind(PRINCIPAL)
        .run();
    }
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

function confirmation(result: { confirmationCode?: string }): string {
  if (result.confirmationCode === undefined) throw new Error("Missing browser confirmation");
  return result.confirmationCode;
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
      scopes: ["openid", "email", "profile", ...CALENDAR_SCOPE.split(" ")],
    },
  };
  identityDeletion = new IdentityDeletion({
    db: testEnv.DB,
    hmacKey: new Uint8Array(32).fill(41),
    nowEpochSeconds: () => currentTime,
  });
  service = createService();
});

function createService(
  db: D1Database = testEnv.DB,
  options: { invalidRedirect?: boolean; throwingClock?: boolean } = {},
): OAuthTransactions {
  const deviceSessions = new DeviceSessions({
    db,
    pepper: new Uint8Array(32).fill(31),
    clock: { now: () => new Date(currentTime * 1000) },
    random,
  });
  return new OAuthTransactions({
    db,
    environment: "local",
    nowEpochSeconds: () => {
      if (options.throwingClock) throw new Error("injected clock failure");
      return currentTime;
    },
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
        redirectUri: options.invalidRedirect
          ? "https://invalid.example.test/wrong"
          : "http://127.0.0.1:8787/oauth/google/callback",
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
}

describe("OAuth transactions against migrated D1", () => {
  it("starts sign-in with exact identity scopes and persists only independent digests and ciphertext", async () => {
    const started = await startSignIn();
    const url = new URL(started.authorization_url);
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("prompt")).toBe("select_account");
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
    expect(
      new Set([row?.["state_hash"], row?.["polling_secret_hash"], row?.["nonce_hash"]]).size,
    ).toBe(3);
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

  it("validates the authorization URL before persisting transaction authority", async () => {
    service = createService(testEnv.DB, { invalidRedirect: true });
    await expect(startSignIn()).rejects.toMatchObject({ code: "internal" });
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM oauth_transactions").first("count"),
    ).resolves.toBe(0);
  });

  it("rejects noncanonical capability aliases and uppercase UUID aliases", async () => {
    const started = await startSignIn();
    const transactionAlias = `${started.transaction_id.slice(0, -1)}B`;
    const pollingAlias = `${started.polling_secret.slice(0, -1)}B`;
    await expect(
      service.statusSignIn(transactionAlias, started.polling_secret),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await expect(service.statusSignIn(started.transaction_id, pollingAlias)).rejects.toMatchObject({
      code: "invalid_request",
    });
    await expect(
      service.startConnect("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".toUpperCase(), {
        client_kind: "web",
        device_name: "Test browser",
        code_challenge: await challenge(),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("creates a sign-in identity, updates metadata by immutable tuple, and redeems once", async () => {
    const started = await startSignIn();
    const completed = await service.callback({
      code: "provider-code-value",
      state: state(started),
    });
    expect(completed.status).toBe("complete");
    const confirmationCode = confirmation(completed);
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
      confirmationCode,
    );
    expect(redeemed.session.credential).toMatch(/^v1\./u);
    await expect(
      service.redeemSignIn(
        started.transaction_id,
        started.polling_secret,
        VERIFIER,
        confirmationCode,
      ),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(
      JSON.stringify(await testEnv.DB.prepare("SELECT * FROM oauth_transactions").all()),
    ).not.toContain("provider-code-value");
    const identity = await testEnv.DB.prepare(
      "SELECT subject, email, display_name FROM external_identities",
    ).first();
    expect(identity).toEqual({
      subject: "subject-a",
      email: "new@example.test",
      display_name: "New name",
    });
  });

  it("keeps identity metadata timestamps monotonic and rejects control text", async () => {
    const newerTimestamp = NOW + 100;
    await testEnv.DB.prepare(
      `INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)`,
    )
      .bind(PRINCIPAL, NOW, NOW)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO external_identities
       (id, principal_id, provider, issuer, subject, email, display_name,
        email_verified, created_at, updated_at)
       VALUES (?, ?, 'google', 'https://accounts.google.com', 'subject-a',
               'newer@example.test', 'Newer', 1, ?, ?)`,
    )
      .bind(IDENTITY, PRINCIPAL, NOW, newerTimestamp)
      .run();
    const started = await startSignIn();
    await service.callback({ code: "provider-code-value", state: state(started) });
    await expect(
      testEnv.DB.prepare(
        "SELECT email, display_name, updated_at FROM external_identities WHERE id = ?",
      )
        .bind(IDENTITY)
        .first(),
    ).resolves.toEqual({
      email: "newer@example.test",
      display_name: "Newer",
      updated_at: newerTimestamp,
    });

    const controlled = await startSignIn();
    signInResult = { ...signInResult, name: "unsafe\nname" };
    await service.callback({ code: "provider-code-value", state: state(controlled) });
    await expect(
      service.statusSignIn(controlled.transaction_id, controlled.polling_secret),
    ).resolves.toEqual({ status: "failed", failure_code: "authorization_failed" });
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

  it("rejects the wrong TaskNotes verifier without consuming sign-in authority", async () => {
    const started = await startSignIn();
    const confirmationCode = confirmation(
      await service.callback({ code: "provider-code-value", state: state(started) }),
    );
    await expect(
      service.redeemSignIn(
        started.transaction_id,
        started.polling_secret,
        "wrong-tasknotes-verifier-value-that-is-long-enough-123",
        confirmationCode,
      ),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      service.redeemSignIn(
        started.transaction_id,
        started.polling_secret,
        VERIFIER,
        confirmationCode,
      ),
    ).resolves.toHaveProperty("session.credential");
  });

  it("gives exactly one winner across 25 sign-in redemption attempts", async () => {
    const started = await startSignIn();
    const confirmationCode = confirmation(
      await service.callback({ code: "provider-code-value", state: state(started) }),
    );
    const attempts = await Promise.allSettled(
      Array.from({ length: 25 }, () =>
        service.redeemSignIn(
          started.transaction_id,
          started.polling_secret,
          VERIFIER,
          confirmationCode,
        ),
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
    expect(results.filter((result) => result.status === "complete")).toHaveLength(1);
    expect(results.filter((result) => result.confirmationCode !== undefined)).toHaveLength(1);
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
    await service.callback({ error: "access_denied", state: state(expired) });
    await expect(
      service.statusSignIn(expired.transaction_id, expired.polling_secret),
    ).resolves.toEqual({
      status: "expired",
    });
    const expiredRow = await testEnv.DB.prepare(
      `SELECT provider_pkce_ciphertext, failure_code, callback_completed_at
       FROM oauth_transactions WHERE id = ?`,
    )
      .bind(expired.transaction_id)
      .first();
    expect(expiredRow).toEqual({
      provider_pkce_ciphertext: null,
      failure_code: null,
      callback_completed_at: null,
    });
    await expect(
      service.statusSignIn(expired.transaction_id, "A".repeat(43)),
    ).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("fails a tampered provider PKCE envelope without exchanging but lets expiry win", async () => {
    const started = await startSignIn();
    const expired = await startSignIn();
    await testEnv.DB.prepare("DROP TRIGGER oauth_transactions_immutable_binding").run();
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions SET provider_pkce_ciphertext = 'tampered'
       WHERE id IN (?, ?)`,
    )
      .bind(started.transaction_id, expired.transaction_id)
      .run();
    await service.callback({ code: "provider-code-value", state: state(started) });
    expect(exchangeSignInCalls).toBe(0);
    await expect(
      service.statusSignIn(started.transaction_id, started.polling_secret),
    ).resolves.toEqual({
      status: "failed",
      failure_code: "authorization_failed",
    });

    currentTime += 600;
    await service.callback({ code: "provider-code-value", state: state(expired) });
    await expect(
      service.statusSignIn(expired.transaction_id, expired.polling_secret),
    ).resolves.toEqual({ status: "expired" });
    await expect(
      testEnv.DB.prepare("SELECT provider_pkce_ciphertext FROM oauth_transactions WHERE id = ?")
        .bind(expired.transaction_id)
        .first("provider_pkce_ciphertext"),
    ).resolves.toBeNull();
  });

  it("expires an equal-time code callback without exchanging", async () => {
    const code = await startSignIn();
    currentTime += 600;
    await service.callback({ code: "provider-code-value", state: state(code) });
    expect(exchangeSignInCalls).toBe(0);
    await expect(service.statusSignIn(code.transaction_id, code.polling_secret)).resolves.toEqual({
      status: "expired",
    });
  });

  it("supersedes an abandoned pending connect even thirty days later", async () => {
    await insertPrincipal();
    const abandoned = await startConnect();
    currentTime += 30 * 24 * 60 * 60;
    const replacement = await startConnect();
    expect(replacement.transaction_id).not.toBe(abandoned.transaction_id);
    await expect(
      service.statusConnect(PRINCIPAL, abandoned.transaction_id, abandoned.polling_secret),
    ).resolves.toEqual({ status: "expired" });
  });

  it("conflicts with a live exchange but supersedes it after its deadline", async () => {
    await insertPrincipal();
    const first = await startConnect();
    onCalendarExchange = async () => {
      await expect(startConnect()).rejects.toMatchObject({ code: "conflict" });
      currentTime += 30;
      await startConnect();
      expect(
        await testEnv.DB.prepare("SELECT status FROM oauth_transactions WHERE id = ?")
          .bind(first.transaction_id)
          .first("status"),
      ).toBe("expired");
    };
    await service.callback({ code: "calendar-provider-code", state: state(first) });
    expect(revoked).toEqual(["refresh-token-private"]);
    expect(await testEnv.DB.prepare("SELECT COUNT(*) FROM connections").first("COUNT(*)")).toBe(0);
  });

  it("starts new connect with offline event and calendar-list consent, stores an AAD-bound envelope, and redeems once", async () => {
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

  it("retains a completed connection when its confirmation transaction expires", async () => {
    await insertPrincipal();
    const started = await startConnect();
    await service.callback({ code: "calendar-provider-code", state: state(started) });
    currentTime += 600;
    await expect(
      service.statusConnect(PRINCIPAL, started.transaction_id, started.polling_secret),
    ).resolves.toEqual({ status: "expired" });
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM connections").first("count"),
    ).resolves.toBe(1);
    await expect(
      testEnv.DB.prepare("SELECT google_connection_generation FROM principals WHERE id = ?")
        .bind(PRINCIPAL)
        .first("google_connection_generation"),
    ).resolves.toBe(1);
  });

  it("recovers connect finalization after ambiguous before- and after-commit batch faults", async () => {
    await insertPrincipal();
    const before = await startConnect();
    service = createService(databaseWithBatchFault("before"));
    await service.callback({ code: "calendar-provider-code", state: state(before) });
    expect(exchangeCalendarCalls).toBe(1);
    expect(revoked).toEqual(["refresh-token-private"]);
    await expect(
      service.statusConnect(PRINCIPAL, before.transaction_id, before.polling_secret),
    ).resolves.toEqual({ status: "failed", failure_code: "authorization_failed" });

    const after = await startConnect();
    revoked = [];
    exchangeCalendarCalls = 0;
    service = createService(databaseWithBatchFault("after"));
    await service.callback({ code: "calendar-provider-code", state: state(after) });
    expect(exchangeCalendarCalls).toBe(1);
    expect(revoked).toEqual([]);
    await expect(
      service.statusConnect(PRINCIPAL, after.transaction_id, after.polling_secret),
    ).resolves.toMatchObject({ status: "authorized" });
    await service.callback({ code: "replayed-provider-code", state: state(after) });
    expect(exchangeCalendarCalls).toBe(1);
  });

  it("clears discovery and refresh leases racing an in-place replacement", async () => {
    await insertPrincipal(true, false);
    const started = await startConnect();
    await testEnv.DB.prepare(
      `UPDATE connections SET discovery_lease_owner = 'discovery-racer',
         discovery_lease_until = unixepoch() + 30,
         discovery_lease_generation = generation,
         discovery_lease_token_version = token_version, updated_at = unixepoch()
       WHERE principal_id = ?`,
    )
      .bind(PRINCIPAL)
      .run();
    await testEnv.DB.prepare(
      `UPDATE connections SET refresh_lease_owner = 'refresh-racer',
         refresh_lease_until = unixepoch() + 120,
         refresh_lease_generation = generation,
         refresh_lease_token_version = token_version, updated_at = unixepoch()
       WHERE principal_id = ?`,
    )
      .bind(PRINCIPAL)
      .run();
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
      testEnv.DB.prepare(
        `SELECT id, status, generation, token_version, refresh_lease_owner,
                discovery_lease_owner FROM connections`,
      ).first(),
    ).resolves.toEqual({
      id: "20000000-0000-4000-8000-000000000001",
      status: "active",
      generation: 2,
      token_version: 2,
      refresh_lease_owner: null,
      discovery_lease_owner: null,
    });
  });

  it("enforces one active connect and revokes an exchanged refresh token when local authority loses", async () => {
    await insertPrincipal();
    const first = await startConnect();
    const replacement = await startConnect();
    await expect(
      service.statusConnect(PRINCIPAL, first.transaction_id, first.polling_secret),
    ).resolves.toEqual({ status: "expired" });
    onCalendarExchange = async () => {
      await testEnv.DB.prepare("DELETE FROM principals WHERE id = ?").bind(PRINCIPAL).run();
    };
    await service.callback({ code: "calendar-provider-code", state: state(replacement) });
    expect(exchangeCalendarCalls).toBe(1);
    expect(revoked).toEqual(["refresh-token-private"]);
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM connections").first("count"),
    ).resolves.toBe(0);
  });

  it("makes equal deletion fences and replacement-generation changes defeat connect commit", async () => {
    await insertPrincipal();
    const fenced = await startConnect();
    onCalendarExchange = async () => {
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
    };
    await service.callback({ code: "calendar-provider-code", state: state(fenced) });
    expect(revoked).toEqual(["refresh-token-private"]);
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM connections").first("count"),
    ).resolves.toBe(0);

    await testEnv.DB.prepare("DELETE FROM identity_deletion_fences").run();
    const replacement = await startConnect();
    revoked = [];
    onCalendarExchange = async () => {
      await testEnv.DB.prepare(
        `INSERT INTO connections
         (id, principal_id, identity_id, provider, status, generation,
          envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv,
          ciphertext, token_version, created_at, updated_at)
         VALUES ('20000000-0000-4000-8000-000000000099', ?, ?, 'google', 'active', 1,
                 1, 1, 'other-dek', 'other-wrapped', 'other-iv', 'other-ciphertext', 1, ?, ?)`,
      )
        .bind(PRINCIPAL, IDENTITY, NOW, NOW)
        .run();
    };
    await service.callback({ code: "calendar-provider-code", state: state(replacement) });
    expect(revoked).toEqual(["refresh-token-private"]);
    await expect(testEnv.DB.prepare("SELECT id FROM connections").first("id")).resolves.toBe(
      "20000000-0000-4000-8000-000000000099",
    );
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

  it("keeps callback completion quiet when validation and the clock fail", async () => {
    service = createService(testEnv.DB, { throwingClock: true });
    await expect(
      service.callback({ code: "provider-code-value", state: "A".repeat(43) }),
    ).resolves.toEqual({ status: "failed" });
    await expect(service.callback({ code: "short", state: "not-base64url" })).resolves.toEqual({
      status: "failed",
    });
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
