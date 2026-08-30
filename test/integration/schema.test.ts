import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;

async function insertPrincipal(id: string): Promise<void> {
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, state, generation, created_at, last_active_at) VALUES (?, 'active', 1, ?, ?)",
  )
    .bind(id, "2026-08-30T00:00:00.000Z", "2026-08-30T00:00:00.000Z")
    .run();
}

beforeEach(async () => {
  await testEnv.DB.batch([
    testEnv.DB.prepare("DELETE FROM principals"),
    testEnv.DB.prepare("DELETE FROM oauth_transactions"),
  ]);
});

describe("initial D1 schema", () => {
  it("enforces immutable identity uniqueness while allowing duplicate email metadata", async () => {
    await insertPrincipal("principal-a");
    await insertPrincipal("principal-b");

    const insertIdentity = (id: string, principalId: string, subject: string) =>
      testEnv.DB.prepare(
        `INSERT INTO external_identities
          (id, principal_id, provider, issuer, subject, email, display_name, email_verified, created_at, updated_at)
         VALUES (?, ?, 'google', 'https://accounts.google.com', ?, 'same@example.test', NULL, 1, ?, ?)`,
      )
        .bind(id, principalId, subject, "2026-08-30T00:00:00.000Z", "2026-08-30T00:00:00.000Z")
        .run();

    await expect(insertIdentity("identity-a", "principal-a", "subject-a")).resolves.toMatchObject({
      success: true,
    });
    await expect(insertIdentity("identity-b", "principal-b", "subject-b")).resolves.toMatchObject({
      success: true,
    });
    await expect(
      insertIdentity("identity-duplicate", "principal-b", "subject-a"),
    ).rejects.toThrow();

    const identities = await testEnv.DB.prepare(
      "SELECT principal_id, subject, email FROM external_identities ORDER BY subject",
    ).all();
    expect(identities.results).toEqual([
      {
        principal_id: "principal-a",
        subject: "subject-a",
        email: "same@example.test",
      },
      {
        principal_id: "principal-b",
        subject: "subject-b",
        email: "same@example.test",
      },
    ]);
  });

  it("rejects invalid states, providers, generations, and client kinds in D1", async () => {
    await expect(
      testEnv.DB.prepare(
        "INSERT INTO principals (id, state, generation, created_at, last_active_at) VALUES ('bad-state', 'disabled', 1, 'now', 'now')",
      ).run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        "INSERT INTO principals (id, state, generation, created_at, last_active_at) VALUES ('bad-generation', 'active', 0, 'now', 'now')",
      ).run(),
    ).rejects.toThrow();

    await insertPrincipal("principal-a");
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO device_sessions
          (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at, idle_expires_at, absolute_expires_at)
         VALUES ('session-a', 'principal-a', 'digest', 'device', 'unknown', 'now', 'now', 'later', 'later')`,
      ).run(),
    ).rejects.toThrow();
  });

  it("cascades principal deletion through identity and session authority", async () => {
    await insertPrincipal("principal-a");
    await testEnv.DB.prepare(
      `INSERT INTO external_identities
        (id, principal_id, provider, issuer, subject, email, display_name, email_verified, created_at, updated_at)
       VALUES ('identity-a', 'principal-a', 'google', 'https://accounts.google.com', 'subject-a', NULL, NULL, 0, 'now', 'now')`,
    ).run();
    await testEnv.DB.prepare(
      `INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at, idle_expires_at, absolute_expires_at)
       VALUES ('session-a', 'principal-a', 'digest', 'device', 'web', 'now', 'now', 'later', 'later')`,
    ).run();

    await testEnv.DB.prepare("DELETE FROM principals WHERE id = 'principal-a'").run();

    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM external_identities").first("count"),
    ).resolves.toBe(0);
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM device_sessions").first("count"),
    ).resolves.toBe(0);
  });
});
