import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import { DeviceSessionInputError, DeviceSessions } from "../../src/auth/device-sessions";
import type { Clock, CreatedDeviceSession, DeviceClientKind } from "../../src/auth/device-sessions";
import type { RandomByteSource } from "../../src/crypto/random";
import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const START = Date.parse("2026-01-01T00:00:00.000Z");
const DAY = 24 * 60 * 60 * 1_000;

class MutableClock implements Clock {
  public milliseconds = START;

  public now(): Date {
    return new Date(this.milliseconds);
  }
}

class CountingRandom implements RandomByteSource {
  #next = 1;

  public bytes(length: number): Uint8Array {
    const value = this.#next;
    this.#next += 1;
    return new Uint8Array(length).fill(value);
  }
}

interface StoredSession {
  id: string;
  principal_id: string;
  credential_hash: string;
  device_name: string;
  client_kind: string;
  last_used_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
  redemption_transaction_id: string | null;
}

let clock: MutableClock;
let sessions: DeviceSessions;

async function addPrincipal(id: string): Promise<void> {
  const timestamp = Math.floor(START / 1_000);
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(id, timestamp, timestamp)
    .run();
}

async function addGoogleIdentity(id: string, principalId: string, subject: string): Promise<void> {
  const timestamp = Math.floor(START / 1_000);
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
      (id, principal_id, provider, issuer, subject, email, display_name, email_verified, created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', ?, 'same@example.test', NULL, 1, ?, ?)`,
  )
    .bind(id, principalId, subject, timestamp, timestamp)
    .run();
}

async function addAuthorizedSignIn(
  id: string,
  principalId: string,
  identityId: string,
  overrides: {
    pollingDigest?: string;
    challenge?: string;
    expiresAt?: number;
    deviceName?: string;
    clientKind?: DeviceClientKind;
  } = {},
): Promise<void> {
  const now = START / 1_000;
  const expiresAt = overrides.expiresAt ?? now + 600;
  const completedAt = Math.min(now, expiresAt - 1);
  await testEnv.DB.prepare(
    `INSERT INTO oauth_transactions
      (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
       tasknotes_pkce_challenge, authorized_principal_id, authorized_identity_id,
       exchange_started_at, exchange_deadline_at, device_name, client_kind,
       created_at, expires_at, callback_completed_at, confirmation_code_hash)
     VALUES (?, 'sign_in', 'authorized', ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      `state-${id}`,
      `nonce-${id}`,
      overrides.pollingDigest ?? `poll-${id}`,
      overrides.challenge ?? `challenge-${id}`,
      principalId,
      identityId,
      now - 5,
      completedAt,
      overrides.deviceName ?? "Redeemed browser",
      overrides.clientKind ?? "web",
      now - 10,
      expiresAt,
      completedAt,
      "C".repeat(43),
    )
    .run();
}

async function createSession(input: {
  principalId: string;
  deviceName: string;
  clientKind: DeviceClientKind;
}): Promise<CreatedDeviceSession> {
  let identityId = await testEnv.DB.prepare(
    "SELECT id FROM external_identities WHERE principal_id = ?",
  )
    .bind(input.principalId)
    .first<string>("id");
  if (identityId === null) {
    identityId = crypto.randomUUID();
    await addGoogleIdentity(identityId, input.principalId, identityId);
  }
  const transactionId = crypto.randomUUID();
  await addAuthorizedSignIn(transactionId, input.principalId, identityId, input);
  const redeemed = await sessions.redeemSignInTransaction({
    transactionId,
    expectedPollingDigest: `poll-${transactionId}`,
    expectedTasknotesPkceChallenge: `challenge-${transactionId}`,
    expectedConfirmationDigest: "C".repeat(43),
  });
  if (redeemed === null) throw new Error("expected redeemed fixture session");
  return redeemed;
}

async function addAuthorizedConnect(
  id: string,
  principalId: string,
  identityId: string,
): Promise<void> {
  const now = START / 1_000;
  await testEnv.DB.prepare(
    `INSERT INTO connections
      (id, principal_id, identity_id, provider, status, generation,
       envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
       token_version, created_at, updated_at)
     VALUES (?, ?, ?, 'google', 'active', 1, 1, 1, 'dek', 'wrapped', 'payload',
             'ciphertext', 1, ?, ?)`,
  )
    .bind(`connection-${id}`, principalId, identityId, now, now)
    .run();
  await testEnv.DB.prepare(
    `INSERT INTO oauth_transactions
      (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
       tasknotes_pkce_challenge, authenticated_principal_id, expected_identity_id,
       expected_connection_generation, expected_connection_id, expected_token_version,
       target_connection_id, target_connection_generation, target_token_version,
       authorized_principal_id, authorized_identity_id, authorized_connection_id,
       exchange_started_at, exchange_deadline_at, device_name, client_kind,
       created_at, expires_at, callback_completed_at)
     VALUES (?, 'connect_calendar', 'authorized', ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, 2, 2,
             ?, ?, ?, ?, ?, 'Browser', 'web', ?, ?, ?)`,
  )
    .bind(
      id,
      `state-${id}`,
      `nonce-${id}`,
      `poll-${id}`,
      `challenge-${id}`,
      principalId,
      identityId,
      `connection-${id}`,
      `connection-${id}`,
      principalId,
      identityId,
      `connection-${id}`,
      now - 5,
      now + 5,
      now - 10,
      now + 600,
      now,
    )
    .run();
}

async function storedSession(id: string): Promise<StoredSession> {
  const row = await testEnv.DB.prepare(
    `SELECT id, principal_id, credential_hash, device_name, client_kind, last_used_at,
            idle_expires_at, absolute_expires_at, revoked_at, redemption_transaction_id
     FROM device_sessions WHERE id = ?`,
  )
    .bind(id)
    .first<StoredSession>();
  if (row === null) {
    throw new Error("expected stored session");
  }
  return row;
}

beforeEach(async () => {
  await testEnv.DB.prepare("DELETE FROM oauth_transactions").run();
  await testEnv.DB.prepare("DELETE FROM principals").run();
  clock = new MutableClock();
  sessions = new DeviceSessions({
    db: testEnv.DB,
    pepper: new Uint8Array(32).fill(91),
    clock,
    random: new CountingRandom(),
  });
});

describe("device sessions against migrated D1", () => {
  it("transactionally caps a principal at 100 active sessions under 101 concurrent redemptions", async () => {
    await addPrincipal("principal-limit");
    await addGoogleIdentity("identity-limit", "principal-limit", "subject-limit");
    const transactionIds = Array.from({ length: 101 }, (_, index) => `transaction-limit-${index}`);
    for (const transactionId of transactionIds) {
      await addAuthorizedSignIn(transactionId, "principal-limit", "identity-limit");
    }
    const outcomes = await Promise.all(
      transactionIds.map((transactionId) =>
        sessions.redeemSignInTransaction({
          transactionId,
          expectedPollingDigest: `poll-${transactionId}`,
          expectedTasknotesPkceChallenge: `challenge-${transactionId}`,
          expectedConfirmationDigest: "C".repeat(43),
        }),
      ),
    );
    expect(outcomes.filter((outcome) => outcome !== null)).toHaveLength(100);
    expect(outcomes.filter((outcome) => outcome === null)).toHaveLength(1);
    expect(
      await testEnv.DB.prepare(
        "SELECT COUNT(*) AS count FROM device_sessions WHERE principal_id = ? AND revoked_at IS NULL",
      )
        .bind("principal-limit")
        .first(),
    ).toEqual({ count: 100 });
    await expect(sessions.list("principal-limit")).resolves.toHaveLength(100);
  });

  it("applies the same active-session cap during atomic sign-in redemption", async () => {
    await addPrincipal("principal-redemption-limit");
    await addGoogleIdentity(
      "identity-redemption-limit",
      "principal-redemption-limit",
      "subject-redemption-limit",
    );
    for (let index = 0; index < 100; index += 1) {
      await createSession({
        principalId: "principal-redemption-limit",
        deviceName: `Existing ${index + 1}`,
        clientKind: "web",
      });
    }
    await addAuthorizedSignIn(
      "transaction-redemption-limit",
      "principal-redemption-limit",
      "identity-redemption-limit",
    );
    await expect(
      sessions.redeemSignInTransaction({
        transactionId: "transaction-redemption-limit",
        expectedPollingDigest: "poll-transaction-redemption-limit",
        expectedTasknotesPkceChallenge: "challenge-transaction-redemption-limit",
        expectedConfirmationDigest: "C".repeat(43),
      }),
    ).resolves.toBeNull();
    await expect(
      testEnv.DB.prepare("SELECT status FROM oauth_transactions WHERE id = ?")
        .bind("transaction-redemption-limit")
        .first("status"),
    ).resolves.toBe("authorized");
  });

  it("returns a 256-bit opaque secret once and persists only a keyed digest", async () => {
    await addPrincipal("principal-a");

    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Callum's phone",
      clientKind: "android",
    });
    const stored = await storedSession(created.id);
    const credentialParts = created.credential.split(".");

    expect(credentialParts).toHaveLength(3);
    expect(credentialParts[0]).toBe("v1");
    expect(credentialParts[1]).toBe(created.id);
    expect(credentialParts[2]).toHaveLength(43); // unpadded base64url for exactly 32 bytes
    expect(stored.credential_hash).toHaveLength(43);
    expect(stored.credential_hash).not.toBe(credentialParts[2]);
    expect(JSON.stringify(stored)).not.toContain(created.credential);
    expect(JSON.stringify(stored)).not.toContain(credentialParts[2]);
    expect(stored).toMatchObject({
      principal_id: "principal-a",
      device_name: "Callum's phone",
      last_used_at: START / 1_000,
      idle_expires_at: (START + 30 * DAY) / 1_000,
      absolute_expires_at: (START + 90 * DAY) / 1_000,
      revoked_at: null,
    });

    await expect(sessions.authenticate(created.credential)).resolves.toMatchObject({
      principalId: "principal-a",
      session: { id: created.id, clientKind: "android" },
    });
  });

  it("authenticates concurrent hourly usage updates and advances principal activity", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Browser",
      clientKind: "web",
    });
    clock.milliseconds += 60 * 60 * 1_000;
    const results = await Promise.all(
      Array.from({ length: 6 }, () => sessions.authenticate(created.credential)),
    );
    expect(results.every((result) => result !== null)).toBe(true);
    expect(
      await testEnv.DB.prepare("SELECT last_active_at FROM principals WHERE id = ?")
        .bind("principal-a")
        .first("last_active_at"),
    ).toBe(clock.milliseconds / 1_000);
    await sessions.revoke("principal-a", created.id);
    await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
  });

  it.each(["revocation", "expiry"] as const)(
    "fails closed when %s races an hourly update",
    async (race) => {
      await addPrincipal("principal-a");
      const created = await createSession({
        principalId: "principal-a",
        deviceName: "Browser",
        clientKind: "web",
      });
      clock.milliseconds += 60 * 60 * 1_000;
      const timestamp = clock.milliseconds / 1_000;
      const assignment =
        race === "revocation" ? `revoked_at = ${timestamp}` : `idle_expires_at = ${timestamp}`;
      await testEnv.DB.prepare(
        `CREATE TRIGGER test_usage_race BEFORE UPDATE OF last_used_at ON device_sessions
      BEGIN UPDATE device_sessions SET ${assignment} WHERE id = OLD.id; SELECT RAISE(IGNORE); END`,
      ).run();
      try {
        await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
        await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
      } finally {
        await testEnv.DB.prepare("DROP TRIGGER test_usage_race").run();
      }
    },
  );

  it("does not use matching email metadata as identity or authority", async () => {
    await addPrincipal("principal-a");
    await addPrincipal("principal-b");
    await addGoogleIdentity("identity-a", "principal-a", "immutable-subject-a");
    await addGoogleIdentity("identity-b", "principal-b", "immutable-subject-b");
    const first = await createSession({
      principalId: "principal-a",
      deviceName: "First",
      clientKind: "web",
    });
    const second = await createSession({
      principalId: "principal-b",
      deviceName: "Second",
      clientKind: "ios",
    });

    await expect(sessions.authenticate(first.credential)).resolves.toMatchObject({
      principalId: "principal-a",
    });
    await expect(sessions.list("principal-a")).resolves.toEqual([
      expect.objectContaining({ id: first.id, deviceName: "First" }),
    ]);
    await expect(sessions.list("principal-b")).resolves.toEqual([
      expect.objectContaining({ id: second.id, deviceName: "Second" }),
    ]);
  });

  it("rejects malformed credentials without broadening locator lookup", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Browser",
      clientKind: "web",
    });
    const [, id, secret] = created.credential.split(".");
    const malformed = [
      "",
      "v1",
      `v2.${id}.${secret}`,
      `v1.${id}`,
      `v1.${id}.${secret}.extra`,
      `v1.${id}.${secret}=`,
      `v1.${id}.${secret?.replace(/.$/u, "B")}`,
      `v1.${id}.short`,
      `v1.short.${secret}`,
      `v1.${id}.${"a".repeat(10_000)}`,
      `v1.${id?.replace(/.$/u, "+")}.${secret}`,
    ];

    for (const credential of malformed) {
      await expect(sessions.authenticate(credential)).resolves.toBeNull();
    }
    await expect(sessions.authenticate(created.credential)).resolves.not.toBeNull();
  });

  it("does not accept the stored digest as the bearer secret", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Browser",
      clientKind: "web",
    });
    const stored = await storedSession(created.id);

    await expect(
      sessions.authenticate(`v1.${created.id}.${stored.credential_hash}`),
    ).resolves.toBeNull();
  });

  it("rejects locator substitution and cross-principal revocation indistinguishably", async () => {
    await addPrincipal("principal-a");
    await addPrincipal("principal-b");
    const first = await createSession({
      principalId: "principal-a",
      deviceName: "First",
      clientKind: "web",
    });
    const second = await createSession({
      principalId: "principal-b",
      deviceName: "Second",
      clientKind: "ios",
    });
    const firstSecret = first.credential.split(".")[2];

    await expect(sessions.authenticate(`v1.${second.id}.${firstSecret}`)).resolves.toBeNull();
    await expect(sessions.revoke("principal-a", second.id)).resolves.toBe(false);
    await expect(sessions.revoke("principal-a", "nonexistent-session-id")).resolves.toBe(false);
    expect((await storedSession(second.id)).revoked_at).toBeNull();
    await expect(sessions.authenticate(second.credential)).resolves.not.toBeNull();
  });

  it("fails at idle and absolute expiry boundaries", async () => {
    await addPrincipal("principal-a");
    const idle = await createSession({
      principalId: "principal-a",
      deviceName: "Idle boundary",
      clientKind: "obsidian",
    });
    const absolute = await createSession({
      principalId: "principal-a",
      deviceName: "Absolute boundary",
      clientKind: "android",
    });
    await testEnv.DB.prepare(
      "UPDATE device_sessions SET idle_expires_at = absolute_expires_at WHERE id = ?",
    )
      .bind(absolute.id)
      .run();
    clock.milliseconds = START + 30 * DAY;
    await expect(sessions.authenticate(idle.credential)).resolves.toBeNull();
    clock.milliseconds = START + 90 * DAY - 1;
    await expect(sessions.authenticate(absolute.credential)).resolves.not.toBeNull();
    clock.milliseconds = START + 90 * DAY;
    await expect(sessions.authenticate(absolute.credential)).resolves.toBeNull();
  });

  it("throttles usage writes to hourly and caps idle expiry at absolute expiry", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Frequently used",
      clientKind: "ios",
    });

    clock.milliseconds = START + 60 * 60 * 1_000 - 1;
    await sessions.authenticate(created.credential);
    expect((await storedSession(created.id)).last_used_at).toBe(START / 1_000);

    clock.milliseconds += 1;
    await sessions.authenticate(created.credential);
    let stored = await storedSession(created.id);
    expect(stored.last_used_at).toBe((START + 60 * 60 * 1_000) / 1_000);
    expect(stored.idle_expires_at).toBe((START + 30 * DAY + 60 * 60 * 1_000) / 1_000);

    clock.milliseconds = START + 70 * DAY;
    await testEnv.DB.prepare("UPDATE device_sessions SET idle_expires_at = ? WHERE id = ?")
      .bind((START + 89 * DAY) / 1_000, created.id)
      .run();
    await sessions.authenticate(created.credential);
    stored = await storedSession(created.id);
    expect(stored.last_used_at).toBe((START + 70 * DAY) / 1_000);
    expect(stored.idle_expires_at).toBe(stored.absolute_expires_at);
  });

  it("revokes only an owned session and revoked sessions cannot authenticate", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Old phone",
      clientKind: "android",
    });

    clock.milliseconds += 1234;
    await expect(sessions.revoke("principal-a", created.id)).resolves.toBe(true);
    await expect(sessions.revoke("principal-a", created.id)).resolves.toBe(false);
    expect((await storedSession(created.id)).revoked_at).toBe(Math.floor((START + 1234) / 1_000));
    await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
  });

  it("deletion immediately removes session authority", async () => {
    await addPrincipal("principal-a");
    const created = await createSession({
      principalId: "principal-a",
      deviceName: "Browser",
      clientKind: "web",
    });

    await testEnv.DB.prepare("DELETE FROM principals WHERE id = 'principal-a'").run();
    await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
    await expect(sessions.list("principal-a")).resolves.toEqual([]);
  });

  it("strictly validates principal identifiers and pepper size", async () => {
    await expect(sessions.list("")).rejects.toBeInstanceOf(DeviceSessionInputError);
    expect(
      () =>
        new DeviceSessions({
          db: testEnv.DB,
          pepper: new Uint8Array(31),
          clock,
          random: new CountingRandom(),
        }),
    ).toThrow("session pepper must be exactly 32 bytes");
  });

  it("atomically redeems an authorized sign-in once without storing the credential", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-success", "principal-a", "identity-a");

    const redeemed = await sessions.redeemSignInTransaction({
      transactionId: "transaction-success",
      expectedPollingDigest: "poll-transaction-success",
      expectedTasknotesPkceChallenge: "challenge-transaction-success",
      expectedConfirmationDigest: "C".repeat(43),
    });
    expect(redeemed).toMatchObject({
      deviceName: "Redeemed browser",
      clientKind: "web",
      createdAt: new Date(START).toISOString(),
    });
    if (redeemed === null) {
      throw new Error("expected redeemed session");
    }

    const stored = await storedSession(redeemed.id);
    expect(stored.redemption_transaction_id).toBe("transaction-success");
    expect(stored.credential_hash).not.toBe(redeemed.credential);
    expect(JSON.stringify(stored)).not.toContain(redeemed.credential);
    expect(JSON.stringify(stored)).not.toContain(redeemed.credential.split(".")[2]);
    await expect(sessions.authenticate(redeemed.credential)).resolves.toMatchObject({
      principalId: "principal-a",
      session: { id: redeemed.id },
    });
    await expect(
      testEnv.DB.prepare(
        "SELECT status, consumed_at, typeof(consumed_at) AS consumed_type FROM oauth_transactions WHERE id = ?",
      )
        .bind("transaction-success")
        .first(),
    ).resolves.toEqual({
      status: "consumed",
      consumed_at: START / 1_000,
      consumed_type: "integer",
    });
  });

  it("allows exactly one winner across twenty concurrent redemptions and rejects replay", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-race", "principal-a", "identity-a");
    const input = {
      transactionId: "transaction-race",
      expectedPollingDigest: "poll-transaction-race",
      expectedTasknotesPkceChallenge: "challenge-transaction-race",
      expectedConfirmationDigest: "C".repeat(43),
    } as const;

    const attempts = await Promise.all(
      Array.from({ length: 20 }, async () => sessions.redeemSignInTransaction(input)),
    );
    const winners = attempts.filter((attempt) => attempt !== null);
    expect(winners).toHaveLength(1);
    await expect(
      testEnv.DB.prepare(
        "SELECT COUNT(*) AS count FROM device_sessions WHERE redemption_transaction_id = ?",
      )
        .bind("transaction-race")
        .first("count"),
    ).resolves.toBe(1);
    await expect(sessions.redeemSignInTransaction(input)).resolves.toBeNull();
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM device_sessions").first("count"),
    ).resolves.toBe(1);
  });

  it("returns unavailable for mismatched binding, intent, expiry, and deleted principal", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-binding", "principal-a", "identity-a");
    const input = {
      transactionId: "transaction-binding",
      expectedPollingDigest: "poll-transaction-binding",
      expectedTasknotesPkceChallenge: "challenge-transaction-binding",
      expectedConfirmationDigest: "C".repeat(43),
    } as const;

    await expect(
      sessions.redeemSignInTransaction({ ...input, expectedPollingDigest: "wrong-poll" }),
    ).resolves.toBeNull();
    await expect(
      sessions.redeemSignInTransaction({
        ...input,
        expectedTasknotesPkceChallenge: "wrong-challenge",
        expectedConfirmationDigest: "C".repeat(43),
      }),
    ).resolves.toBeNull();

    await addAuthorizedConnect("transaction-connect", "principal-a", "identity-a");
    await expect(
      sessions.redeemSignInTransaction({
        transactionId: "transaction-connect",
        expectedPollingDigest: "poll-transaction-connect",
        expectedTasknotesPkceChallenge: "challenge-transaction-connect",
        expectedConfirmationDigest: "C".repeat(43),
      }),
    ).resolves.toBeNull();

    await addAuthorizedSignIn("transaction-expired", "principal-a", "identity-a", {
      expiresAt: START / 1_000,
    });
    await expect(
      sessions.redeemSignInTransaction({
        transactionId: "transaction-expired",
        expectedPollingDigest: "poll-transaction-expired",
        expectedTasknotesPkceChallenge: "challenge-transaction-expired",
        expectedConfirmationDigest: "C".repeat(43),
      }),
    ).resolves.toBeNull();

    await addPrincipal("principal-deleted");
    await addGoogleIdentity("identity-deleted", "principal-deleted", "subject-deleted");
    await addAuthorizedSignIn("transaction-deleted", "principal-deleted", "identity-deleted");
    await testEnv.DB.prepare("DELETE FROM principals WHERE id = 'principal-deleted'").run();
    await expect(
      sessions.redeemSignInTransaction({
        transactionId: "transaction-deleted",
        expectedPollingDigest: "poll-transaction-deleted",
        expectedTasknotesPkceChallenge: "challenge-transaction-deleted",
        expectedConfirmationDigest: "C".repeat(43),
      }),
    ).resolves.toBeNull();

    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM device_sessions").first("count"),
    ).resolves.toBe(0);
  });

  it("rejects malformed redemption bindings before querying D1", async () => {
    const valid = {
      transactionId: "transaction-input",
      expectedPollingDigest: "poll-transaction-input",
      expectedTasknotesPkceChallenge: "challenge-transaction-input",
      expectedConfirmationDigest: "C".repeat(43),
    } as const;
    for (const input of [
      { ...valid, transactionId: "x".repeat(257) },
      { ...valid, expectedPollingDigest: "poll\u0000digest" },
      { ...valid, expectedTasknotesPkceChallenge: "x".repeat(129) },
      { ...valid, expectedConfirmationDigest: "" },
    ]) {
      await expect(sessions.redeemSignInTransaction(input)).rejects.toBeInstanceOf(
        DeviceSessionInputError,
      );
    }
  });

  it("does not mint a replacement after a committed response is lost", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-lost", "principal-a", "identity-a");
    const input = {
      transactionId: "transaction-lost",
      expectedPollingDigest: "poll-transaction-lost",
      expectedTasknotesPkceChallenge: "challenge-transaction-lost",
      expectedConfirmationDigest: "C".repeat(43),
    } as const;

    await sessions.redeemSignInTransaction(input); // Simulate committing before the response is lost.
    await expect(sessions.redeemSignInTransaction(input)).resolves.toBeNull();
    const rows = await testEnv.DB.prepare(
      `SELECT credential_hash, redemption_transaction_id
       FROM device_sessions WHERE redemption_transaction_id = ?`,
    )
      .bind("transaction-lost")
      .all();
    expect(rows.results).toHaveLength(1);
    expect(JSON.stringify(rows.results)).not.toContain("v1.");
  });

  it("retains a redeemed session when transaction cleanup nulls its redemption link", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-cleanup", "principal-a", "identity-a");
    const redeemed = await sessions.redeemSignInTransaction({
      transactionId: "transaction-cleanup",
      expectedPollingDigest: "poll-transaction-cleanup",
      expectedTasknotesPkceChallenge: "challenge-transaction-cleanup",
      expectedConfirmationDigest: "C".repeat(43),
    });
    if (redeemed === null) {
      throw new Error("expected redeemed session");
    }

    await testEnv.DB.prepare("DELETE FROM oauth_transactions WHERE id = ?")
      .bind("transaction-cleanup")
      .run();
    expect((await storedSession(redeemed.id)).redemption_transaction_id).toBeNull();
    await expect(sessions.authenticate(redeemed.credential)).resolves.not.toBeNull();
  });

  it("rolls back the inserted session when the consume statement fails", async () => {
    await addPrincipal("principal-a");
    await addGoogleIdentity("identity-a", "principal-a", "subject-a");
    await addAuthorizedSignIn("transaction-trigger", "principal-a", "identity-a");
    await testEnv.DB.prepare(
      `CREATE TRIGGER test_reject_consumption
       BEFORE UPDATE OF status ON oauth_transactions
       WHEN NEW.status = 'consumed'
       BEGIN
         SELECT RAISE(ABORT, 'simulated consume failure');
       END`,
    ).run();

    try {
      await expect(
        sessions.redeemSignInTransaction({
          transactionId: "transaction-trigger",
          expectedPollingDigest: "poll-transaction-trigger",
          expectedTasknotesPkceChallenge: "challenge-transaction-trigger",
          expectedConfirmationDigest: "C".repeat(43),
        }),
      ).rejects.toThrow("simulated consume failure");
      await expect(
        testEnv.DB.prepare("SELECT COUNT(*) AS count FROM device_sessions").first("count"),
      ).resolves.toBe(0);
      await expect(
        testEnv.DB.prepare(
          "SELECT status FROM oauth_transactions WHERE id = 'transaction-trigger'",
        ).first("status"),
      ).resolves.toBe("authorized");
    } finally {
      await testEnv.DB.prepare("DROP TRIGGER test_reject_consumption").run();
    }
  });
});
