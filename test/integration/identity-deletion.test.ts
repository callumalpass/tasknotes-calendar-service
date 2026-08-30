import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import { IdentityDeletion, IdentityDeletionInputError } from "../../src/auth/identity-deletion";
import type { GoogleIdentityTuple } from "../../src/auth/identity-deletion";
import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const NOW = 1_788_048_000;
const KEY = new Uint8Array(32).fill(73);
const GOOGLE_IDENTITY = {
  provider: "google",
  issuer: "https://accounts.google.com",
  subject: "immutable-google-subject-a",
} as const satisfies GoogleIdentityTuple;

let deletion: IdentityDeletion;
let currentTime: number;

async function insertPrincipal(id: string, timestamp = NOW): Promise<void> {
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(id, timestamp, timestamp)
    .run();
}

async function insertIdentity(
  id: string,
  principalId: string,
  subject: string,
  email = "same@example.test",
): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
      (id, principal_id, provider, issuer, subject, email, display_name, email_verified,
       created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', ?, ?, NULL, 1, ?, ?)`,
  )
    .bind(id, principalId, subject, email, NOW, NOW)
    .run();
}

async function count(table: string): Promise<number> {
  const value = await testEnv.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<number>(
    "count",
  );
  if (value === null) {
    throw new Error("expected count");
  }
  return value;
}

interface FenceRow {
  identity_digest: string;
  deleted_at: number;
}

async function fenceRows(): Promise<readonly FenceRow[]> {
  const result = await testEnv.DB.prepare(
    "SELECT identity_digest, deleted_at FROM identity_deletion_fences ORDER BY identity_digest",
  ).all<FenceRow>();
  return result.results;
}

async function deleteIdentity(
  overrides: Partial<{
    authenticatedPrincipalId: string;
    identityId: string;
    identity: GoogleIdentityTuple;
    deletedAt: number;
  }> = {},
) {
  const { deletedAt = NOW + 10, ...input } = overrides;
  currentTime = deletedAt;
  return deletion.deletePrincipal({
    authenticatedPrincipalId: "principal-a",
    identityId: "identity-a",
    identity: GOOGLE_IDENTITY,
    ...input,
  });
}

beforeEach(async () => {
  await testEnv.DB.prepare("DELETE FROM oauth_transactions").run();
  await testEnv.DB.prepare("DELETE FROM principals").run();
  await testEnv.DB.prepare("DELETE FROM identity_deletion_fences").run();
  currentTime = NOW + 10;
  deletion = new IdentityDeletion({
    db: testEnv.DB,
    hmacKey: KEY,
    nowEpochSeconds: () => currentTime,
  });
});

describe("identity deletion fencing against migrated D1", () => {
  it("returns the digest used by deletion-wins conditional SQL", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);

    await expect(deleteIdentity()).resolves.toBe("completed");
    const digest = await deletion.fenceDigest(GOOGLE_IDENTITY);
    expect(digest).toHaveLength(43);
    for (const [createdAt, eligible] of [
      [NOW + 9, 0],
      [NOW + 10, 0],
      [NOW + 11, 1],
    ] as const) {
      await expect(
        testEnv.DB.prepare(
          `SELECT NOT EXISTS (
             SELECT 1 FROM identity_deletion_fences
             WHERE identity_digest = ? AND deleted_at >= ?
           ) AS eligible`,
        )
          .bind(digest, createdAt)
          .first("eligible"),
      ).resolves.toBe(eligible);
    }
  });

  it("binds fences to the immutable subject and ignores matching email metadata", async () => {
    const otherIdentity = {
      ...GOOGLE_IDENTITY,
      subject: "immutable-google-subject-b",
    } satisfies GoogleIdentityTuple;
    await insertPrincipal("principal-a");
    await insertPrincipal("principal-b");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);
    await insertIdentity("identity-b", "principal-b", otherIdentity.subject);

    await deleteIdentity();

    expect(await deletion.fenceDigest(GOOGLE_IDENTITY)).not.toBe(
      await deletion.fenceDigest(otherIdentity),
    );
    expect(await count("principals")).toBe(1);
    expect(await testEnv.DB.prepare("SELECT id FROM principals").first("id")).toBe("principal-b");
  });

  it("rejects noncanonical provider, issuer, invalid subjects, and key sizes", async () => {
    const invalidIdentities = [
      { ...GOOGLE_IDENTITY, provider: "microsoft" },
      { ...GOOGLE_IDENTITY, issuer: "accounts.google.com" },
      { ...GOOGLE_IDENTITY, subject: "" },
      { ...GOOGLE_IDENTITY, subject: "x".repeat(256) },
      { ...GOOGLE_IDENTITY, subject: "é".repeat(128) },
      { ...GOOGLE_IDENTITY, subject: "line\nbreak" },
      { ...GOOGLE_IDENTITY, subject: "delete\u007fcontrol" },
    ];
    for (const identity of invalidIdentities) {
      await expect(deletion.fenceDigest(identity as GoogleIdentityTuple)).rejects.toBeInstanceOf(
        IdentityDeletionInputError,
      );
    }
    expect(
      () =>
        new IdentityDeletion({
          db: testEnv.DB,
          hmacKey: new Uint8Array(31),
          nowEpochSeconds: () => NOW,
        }),
    ).toThrow("exactly 32 bytes");
  });

  it("does not mutate a fence or principal for cross-principal deletion", async () => {
    await insertPrincipal("principal-a");
    await insertPrincipal("principal-b");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);

    await expect(deleteIdentity({ authenticatedPrincipalId: "principal-b" })).resolves.toBe(
      "unavailable",
    );

    expect(await count("principals")).toBe(2);
    expect(await count("external_identities")).toBe(1);
    expect(await fenceRows()).toEqual([]);
  });

  it("prevents a stale caller from deleting a newly recreated principal", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);
    await deleteIdentity({ deletedAt: NOW + 10 });
    await insertPrincipal("principal-b", NOW + 11);
    await insertIdentity("identity-b", "principal-b", GOOGLE_IDENTITY.subject);

    await expect(deleteIdentity({ deletedAt: NOW + 20 })).resolves.toBe("unavailable");

    expect(await testEnv.DB.prepare("SELECT id FROM principals").first("id")).toBe("principal-b");
    expect(await testEnv.DB.prepare("SELECT id FROM external_identities").first("id")).toBe(
      "identity-b",
    );
    const rows = await fenceRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.identity_digest).toHaveLength(43);
    expect(rows[0]?.deleted_at).toBe(NOW + 10);
  });

  it("is idempotent and advances an existing fence monotonically", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);

    await expect(deleteIdentity({ deletedAt: NOW + 10 })).resolves.toBe("completed");
    await expect(deleteIdentity({ deletedAt: NOW + 5 })).resolves.toBe("completed");
    let rows = await fenceRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.deleted_at).toBe(NOW + 10);

    const competing = await Promise.all([
      deleteIdentity({ deletedAt: NOW + 20 }),
      deleteIdentity({ deletedAt: NOW + 15 }),
    ]);
    expect(competing).toEqual(["completed", "completed"]);
    rows = await fenceRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.deleted_at).toBe(NOW + 20);
    expect(await count("principals")).toBe(0);
  });

  it("does not create a fence for an unowned identity that was never deleted", async () => {
    await insertPrincipal("principal-a");

    await expect(deleteIdentity()).resolves.toBe("unavailable");

    expect(await count("principals")).toBe(1);
    expect(await fenceRows()).toEqual([]);
  });

  it("stores only a fixed-size keyed digest, not identity or email material", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity(
      "identity-a",
      "principal-a",
      GOOGLE_IDENTITY.subject,
      "private-address@example.test",
    );
    await deleteIdentity();

    const serialized = JSON.stringify(await fenceRows());
    expect(serialized).not.toContain(GOOGLE_IDENTITY.subject);
    expect(serialized).not.toContain(GOOGLE_IDENTITY.issuer);
    expect(serialized).not.toContain("google");
    expect(serialized).not.toContain("private-address@example.test");
    expect((await fenceRows())[0]?.identity_digest).toEqual(expect.any(String));
    expect(String((await fenceRows())[0]?.identity_digest)).toHaveLength(43);
  });

  it("atomically cascades sessions, connections, and calendars while retaining the fence", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);
    await testEnv.DB.prepare(
      `INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at,
         last_used_at, idle_expires_at, absolute_expires_at)
       VALUES ('session-a', 'principal-a', 'digest', 'Phone', 'android', ?, ?, ?, ?)`,
    )
      .bind(NOW, NOW, NOW + 100, NOW + 200)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO connections
        (id, principal_id, identity_id, provider, status, generation,
         envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
         token_version, created_at, updated_at)
       VALUES ('connection-a', 'principal-a', 'identity-a', 'google', 'active', 1,
               1, 1, 'dek', 'wrapped', 'payload', 'ciphertext', 1, ?, ?)`,
    )
      .bind(NOW, NOW)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO calendars
        (id, principal_id, connection_id, provider_calendar_id, name, is_primary,
         discovered_at, updated_at)
       VALUES ('calendar-a', 'principal-a', 'connection-a', 'provider-calendar', 'Main', 1, ?, ?)`,
    )
      .bind(NOW, NOW)
      .run();

    await expect(deleteIdentity()).resolves.toBe("completed");

    for (const table of [
      "principals",
      "external_identities",
      "device_sessions",
      "connections",
      "calendars",
    ]) {
      expect(await count(table)).toBe(0);
    }
    expect(await count("identity_deletion_fences")).toBe(1);
    expect((await testEnv.DB.prepare("PRAGMA foreign_key_check").all()).results).toEqual([]);
  });

  it("prevents delayed session and connection authority from targeting the deleted principal", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", GOOGLE_IDENTITY.subject);
    await deleteIdentity();

    await expect(
      testEnv.DB.prepare(
        `INSERT INTO device_sessions
          (id, principal_id, credential_hash, device_name, client_kind, created_at,
           last_used_at, idle_expires_at, absolute_expires_at)
         VALUES ('late-session', 'principal-a', 'digest', 'Late', 'web', ?, ?, ?, ?)`,
      )
        .bind(NOW, NOW, NOW + 100, NOW + 200)
        .run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO connections
          (id, principal_id, identity_id, provider, status, generation,
           envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
           token_version, created_at, updated_at)
         VALUES ('late-connection', 'principal-a', 'identity-a', 'google', 'active', 1,
                 1, 1, 'dek', 'wrapped', 'payload', 'ciphertext', 1, ?, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();

    expect(await count("device_sessions")).toBe(0);
    expect(await count("connections")).toBe(0);
    expect(await count("identity_deletion_fences")).toBe(1);
  });
});
