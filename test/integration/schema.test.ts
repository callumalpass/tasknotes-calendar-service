import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  decryptTokenEnvelope,
  encryptTokenEnvelope,
  rewrapTokenEnvelope,
} from "../../src/crypto/token-envelope";
import type { KeyEncryptionKeyring, TokenEnvelopeContext } from "../../src/crypto/token-envelope";
import type { Env } from "../../src/env";
import { tokenEnvelopeFromRow, tokenEnvelopeToRow } from "../../src/storage/token-envelope-row";
import type { TokenEnvelopeRow } from "../../src/storage/token-envelope-row";

const testEnv = env as unknown as Env;
const NOW = 1_788_048_000;
const KEY_1 = new Uint8Array(32).fill(1);
const KEY_2 = new Uint8Array(32).fill(2);
const KEYRING: KeyEncryptionKeyring = {
  activeVersion: 1,
  keys: new Map([
    [1, KEY_1],
    [2, KEY_2],
  ]),
};

async function insertPrincipal(id: string): Promise<void> {
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(id, NOW, NOW)
    .run();
}

async function insertIdentity(id: string, principalId: string, subject: string): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
      (id, principal_id, provider, issuer, subject, email, display_name, email_verified, created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', ?, 'same@example.test', NULL, 1, ?, ?)`,
  )
    .bind(id, principalId, subject, NOW, NOW)
    .run();
}

async function insertConnection(
  id: string,
  principalId: string,
  identityId: string,
  overrides: Partial<TokenEnvelopeRow> = {},
): Promise<void> {
  const envelope = {
    envelope_schema_version: 1,
    key_version: 1,
    dek_iv: "dek-iv",
    wrapped_dek: "wrapped-dek",
    payload_iv: "payload-iv",
    ciphertext: "ciphertext",
    ...overrides,
  };
  await testEnv.DB.prepare(
    `INSERT INTO connections
      (id, principal_id, identity_id, provider, status, generation,
       envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
       token_version, created_at, updated_at)
     VALUES (?, ?, ?, 'google', 'active', 1, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
  )
    .bind(
      id,
      principalId,
      identityId,
      envelope.envelope_schema_version,
      envelope.key_version,
      envelope.dek_iv,
      envelope.wrapped_dek,
      envelope.payload_iv,
      envelope.ciphertext,
      NOW,
      NOW,
    )
    .run();
}

async function insertPendingSignIn(id: string): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO oauth_transactions
      (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
       tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
       provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
       provider_pkce_ciphertext, device_name, client_kind, created_at, expires_at)
     VALUES (?, 'sign_in', 'pending', ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, 'Browser', 'web', ?, ?)`,
  )
    .bind(
      id,
      `state-${id}`,
      `nonce-${id}`,
      `poll-${id}`,
      `challenge-${id}`,
      "dek-iv",
      "wrapped-dek",
      "payload-iv",
      "ciphertext",
      NOW,
      NOW + 600,
    )
    .run();
}

beforeEach(async () => {
  await testEnv.DB.prepare("DELETE FROM oauth_transactions").run();
  await testEnv.DB.prepare("DELETE FROM principals").run();
  await testEnv.DB.prepare("DELETE FROM identity_deletion_fences").run();
});

describe("initial D1 schema invariants", () => {
  it("enforces canonical immutable identity while allowing duplicate email metadata", async () => {
    await insertPrincipal("principal-a");
    await insertPrincipal("principal-b");
    await insertIdentity("identity-a", "principal-a", "subject-a");
    await insertIdentity("identity-b", "principal-b", "subject-b");

    await expect(insertIdentity("duplicate-subject", "principal-b", "subject-a")).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO external_identities
          (id, principal_id, provider, issuer, subject, email, email_verified, created_at, updated_at)
         VALUES ('second-for-principal', 'principal-a', 'google', 'https://accounts.google.com',
                 'subject-c', NULL, 0, ?, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO external_identities
          (id, principal_id, provider, issuer, subject, email, email_verified, created_at, updated_at)
         VALUES ('bad-issuer', 'principal-b', 'google', 'accounts.google.com',
                 'subject-d', NULL, 0, ?, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();

    const identities = await testEnv.DB.prepare(
      "SELECT principal_id, subject, email FROM external_identities ORDER BY subject",
    ).all();
    expect(identities.results).toEqual([
      { principal_id: "principal-a", subject: "subject-a", email: "same@example.test" },
      { principal_id: "principal-b", subject: "subject-b", email: "same@example.test" },
    ]);
  });

  it("rejects cross-tenant connection and calendar relationships", async () => {
    await insertPrincipal("principal-a");
    await insertPrincipal("principal-b");
    await insertIdentity("identity-a", "principal-a", "subject-a");
    await insertIdentity("identity-b", "principal-b", "subject-b");
    await insertConnection("connection-a", "principal-a", "identity-a");

    await expect(insertConnection("cross-tenant", "principal-b", "identity-a")).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO calendars
          (id, principal_id, connection_id, provider_calendar_id, name, is_primary,
           discovered_at, updated_at)
         VALUES ('calendar-cross', 'principal-b', 'connection-a', 'provider-id', 'Cross', 0, ?, ?)`,
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow();

    const check = await testEnv.DB.prepare("PRAGMA foreign_key_check").all();
    expect(check.results).toEqual([]);
  });

  it("persists and reconstructs exact token envelopes without coercion", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", "subject-a");
    const context: TokenEnvelopeContext = {
      environment: "local",
      provider: "google",
      principalId: "principal-a",
      connectionId: "connection-a",
      connectionGeneration: 1,
      tokenVersion: 1,
      tokenKind: "google_oauth",
    };
    const payload = {
      accessToken: "access-secret",
      refreshToken: "refresh-secret",
      expiresAtEpochSeconds: NOW + 3600,
      scopes: ["openid", "https://www.googleapis.com/auth/calendar.readonly"],
    };
    const encrypted = await encryptTokenEnvelope(payload, context, KEYRING);
    await insertConnection(
      "connection-a",
      "principal-a",
      "identity-a",
      tokenEnvelopeToRow(encrypted),
    );

    const row = await testEnv.DB.prepare(
      `SELECT envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext
       FROM connections WHERE id = 'connection-a'`,
    ).first<TokenEnvelopeRow>();
    if (row === null) {
      throw new Error("expected persisted token envelope");
    }
    await expect(
      decryptTokenEnvelope(tokenEnvelopeFromRow(row), context, KEYRING),
    ).resolves.toEqual(payload);

    const rotated = await rewrapTokenEnvelope(tokenEnvelopeFromRow(row), context, {
      activeVersion: 2,
      keys: KEYRING.keys,
    });
    const rotatedRow = tokenEnvelopeToRow(rotated);
    const update = await testEnv.DB.prepare(
      `UPDATE connections
       SET envelope_schema_version = ?, key_version = ?, dek_iv = ?, wrapped_dek = ?,
           payload_iv = ?, ciphertext = ?, updated_at = ?
       WHERE id = 'connection-a' AND generation = 1 AND token_version = 1`,
    )
      .bind(
        rotatedRow.envelope_schema_version,
        rotatedRow.key_version,
        rotatedRow.dek_iv,
        rotatedRow.wrapped_dek,
        rotatedRow.payload_iv,
        rotatedRow.ciphertext,
        NOW + 1,
      )
      .run();
    expect(update.meta.changes).toBe(1);
    await expect(
      decryptTokenEnvelope(rotated, context, {
        activeVersion: 2,
        keys: KEYRING.keys,
      }),
    ).resolves.toEqual(payload);
  });

  it("prevents connection version rollback and malformed refresh leases", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", "subject-a");
    await insertConnection("connection-a", "principal-a", "identity-a");

    await testEnv.DB.prepare(
      "UPDATE connections SET generation = 2, token_version = 2, updated_at = ? WHERE id = 'connection-a'",
    )
      .bind(NOW + 1)
      .run();
    await expect(
      testEnv.DB.prepare("UPDATE connections SET generation = 1 WHERE id = 'connection-a'").run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        "UPDATE connections SET token_version = 1 WHERE id = 'connection-a'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        "UPDATE connections SET refresh_lease_owner = 'worker' WHERE id = 'connection-a'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        `UPDATE connections
         SET refresh_lease_owner = 'worker', refresh_lease_until = ?,
             refresh_lease_generation = 1, refresh_lease_token_version = 2
         WHERE id = 'connection-a'`,
      )
        .bind(NOW + 30)
        .run(),
    ).rejects.toThrow();
  });

  it("enforces integer timestamp ordering", async () => {
    await expect(
      testEnv.DB.prepare(
        "INSERT INTO principals (id, created_at, last_active_at) VALUES ('text-time', 'now', 'later')",
      ).run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        "INSERT INTO principals (id, created_at, last_active_at) VALUES ('reversed', ?, ?)",
      )
        .bind(NOW, NOW - 1)
        .run(),
    ).rejects.toThrow();

    await insertPrincipal("principal-a");
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO device_sessions
          (id, principal_id, credential_hash, device_name, client_kind, created_at,
           last_used_at, idle_expires_at, absolute_expires_at)
         VALUES ('bad-session', 'principal-a', 'digest', 'device', 'web', ?, ?, ?, ?)`,
      )
        .bind(NOW, NOW, NOW - 1, NOW + 10)
        .run(),
    ).rejects.toThrow();
  });

  it("enforces OAuth intent, state, timestamp, and transition invariants", async () => {
    await insertPendingSignIn("transaction-a");
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET status = 'consumed', consumed_at = ? WHERE id = 'transaction-a'",
      )
        .bind(NOW + 1)
        .run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET status = 'authorized' WHERE id = 'transaction-a'",
      ).run(),
    ).rejects.toThrow();
    await expect(
      testEnv.DB.prepare("UPDATE oauth_transactions SET expires_at = ? WHERE id = 'transaction-a'")
        .bind(NOW - 1)
        .run(),
    ).rejects.toThrow();

    await expect(
      testEnv.DB.prepare(
        `INSERT INTO oauth_transactions
          (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
           tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
           provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
           provider_pkce_ciphertext, device_name, client_kind, created_at, expires_at)
         VALUES ('bad-connect', 'connect_calendar', 'pending', 's', 'n', 'p', 'c', 1, 1,
                 'i', 'd', 'p', 'x', 'Browser', 'web', ?, ?)`,
      )
        .bind(NOW, NOW + 600)
        .run(),
    ).rejects.toThrow();

    await testEnv.DB.prepare(
      `UPDATE oauth_transactions
       SET status = 'processing', processing_owner = 'callback-a', processing_expires_at = ?
       WHERE id = 'transaction-a'`,
    )
      .bind(NOW + 30)
      .run();
    await expect(
      testEnv.DB.prepare(
        `UPDATE oauth_transactions
         SET status = 'pending', processing_owner = NULL, processing_expires_at = NULL
         WHERE id = 'transaction-a'`,
      ).run(),
    ).rejects.toThrow();
  });

  it("cascades all authority while retaining the identity deletion fence", async () => {
    await insertPrincipal("principal-a");
    await insertIdentity("identity-a", "principal-a", "subject-a");
    await insertConnection("connection-a", "principal-a", "identity-a");
    await testEnv.DB.prepare(
      `INSERT INTO calendars
        (id, principal_id, connection_id, provider_calendar_id, name, is_primary,
         discovered_at, updated_at)
       VALUES ('calendar-a', 'principal-a', 'connection-a', 'provider-calendar', 'Calendar', 1, ?, ?)`,
    )
      .bind(NOW, NOW)
      .run();
    await testEnv.DB.prepare(
      `INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at,
         last_used_at, idle_expires_at, absolute_expires_at)
       VALUES ('session-a', 'principal-a', 'digest', 'device', 'web', ?, ?, ?, ?)`,
    )
      .bind(NOW, NOW, NOW + 100, NOW + 200)
      .run();
    await testEnv.DB.prepare(
      "INSERT INTO identity_deletion_fences (identity_digest, deleted_at) VALUES ('digest-a', ?)",
    )
      .bind(NOW + 1)
      .run();

    await testEnv.DB.prepare("DELETE FROM principals WHERE id = 'principal-a'").run();

    for (const table of [
      "principals",
      "external_identities",
      "device_sessions",
      "connections",
      "calendars",
    ]) {
      await expect(
        testEnv.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first("count"),
      ).resolves.toBe(0);
    }
    await expect(
      testEnv.DB.prepare("SELECT COUNT(*) AS count FROM identity_deletion_fences").first("count"),
    ).resolves.toBe(1);
    const check = await testEnv.DB.prepare("PRAGMA foreign_key_check").all();
    expect(check.results).toEqual([]);
  });
});
