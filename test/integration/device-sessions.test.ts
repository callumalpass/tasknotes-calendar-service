import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DeviceSessionInputError,
  DeviceSessions,
  PrincipalUnavailableError,
} from "../../src/auth/device-sessions";
import type { Clock, DeviceClientKind } from "../../src/auth/device-sessions";
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
  last_used_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
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

async function storedSession(id: string): Promise<StoredSession> {
  const row = await testEnv.DB.prepare(
    `SELECT id, principal_id, credential_hash, device_name, last_used_at,
            idle_expires_at, absolute_expires_at, revoked_at
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
  it("returns a 256-bit opaque secret once and persists only a keyed digest", async () => {
    await addPrincipal("principal-a");

    const created = await sessions.create({
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

  it("does not use matching email metadata as identity or authority", async () => {
    await addPrincipal("principal-a");
    await addPrincipal("principal-b");
    await addGoogleIdentity("identity-a", "principal-a", "immutable-subject-a");
    await addGoogleIdentity("identity-b", "principal-b", "immutable-subject-b");
    const first = await sessions.create({
      principalId: "principal-a",
      deviceName: "First",
      clientKind: "web",
    });
    const second = await sessions.create({
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
    const created = await sessions.create({
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
    const created = await sessions.create({
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
    const first = await sessions.create({
      principalId: "principal-a",
      deviceName: "First",
      clientKind: "web",
    });
    const second = await sessions.create({
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
    const idle = await sessions.create({
      principalId: "principal-a",
      deviceName: "Idle boundary",
      clientKind: "obsidian",
    });
    const absolute = await sessions.create({
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
    const created = await sessions.create({
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
    const created = await sessions.create({
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

  it("requires an existing principal and deletion immediately removes session authority", async () => {
    await addPrincipal("principal-a");
    const created = await sessions.create({
      principalId: "principal-a",
      deviceName: "Browser",
      clientKind: "web",
    });

    await expect(
      sessions.create({
        principalId: "missing-principal",
        deviceName: "Browser",
        clientKind: "web",
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
    await testEnv.DB.prepare("DELETE FROM principals WHERE id = 'principal-a'").run();
    await expect(sessions.authenticate(created.credential)).resolves.toBeNull();
    await expect(sessions.list("principal-a")).resolves.toEqual([]);
  });

  it("strictly validates device names, client kinds, identifiers, and pepper size", async () => {
    await addPrincipal("principal-a");
    const invalidNames = ["", " leading", "trailing ", "line\nbreak", "x".repeat(129)];
    for (const deviceName of invalidNames) {
      await expect(
        sessions.create({ principalId: "principal-a", deviceName, clientKind: "web" }),
      ).rejects.toBeInstanceOf(DeviceSessionInputError);
    }

    await expect(
      sessions.create({
        principalId: "principal-a",
        deviceName: "Browser",
        clientKind: "desktop" as DeviceClientKind,
      }),
    ).rejects.toBeInstanceOf(DeviceSessionInputError);
    await expect(
      sessions.create({ principalId: "", deviceName: "Browser", clientKind: "web" }),
    ).rejects.toBeInstanceOf(DeviceSessionInputError);
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
});
