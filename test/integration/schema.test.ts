import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const NOW = 1_788_048_000;

async function principal(id = "principal-a", generation = 0): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO principals
       (id, google_connection_generation, created_at, last_active_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(id, generation, NOW, NOW)
    .run();
}

async function identity(
  id = "identity-a",
  principalId = "principal-a",
  subject = "subject-a",
): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
       (id, principal_id, provider, issuer, subject, email, display_name, email_verified,
        created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', ?, 'same@example.test', NULL, 1, ?, ?)`,
  )
    .bind(id, principalId, subject, NOW, NOW)
    .run();
}

async function connection(
  id = "connection-a",
  principalId = "principal-a",
  identityId = "identity-a",
  generation = 1,
): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO connections
       (id, principal_id, identity_id, provider, status, generation,
        envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
        token_version, created_at, updated_at)
     VALUES (?, ?, ?, 'google', 'active', ?, 1, 1, 'dek-1', 'wrapped-1', 'payload-1',
             'ciphertext-1', 1, ?, ?)`,
  )
    .bind(id, principalId, identityId, generation, NOW, NOW)
    .run();
}

async function pendingSignIn(id: string): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO oauth_transactions
       (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
        tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
        provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
        provider_pkce_ciphertext, device_name, client_kind, created_at, expires_at)
     VALUES (?, 'sign_in', 'pending', ?, ?, ?, ?, 1, 1, 'dek', 'wrapped', 'payload',
             'ciphertext', 'Browser', 'web', ?, ?)`,
  )
    .bind(id, `state-${id}`, `nonce-${id}`, `poll-${id}`, `challenge-${id}`, NOW, NOW + 600)
    .run();
}

async function pendingConnect(id: string, shape: "new" | "existing" = "new"): Promise<void> {
  await testEnv.DB.prepare(
    `INSERT INTO oauth_transactions
       (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
        tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
        provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
        provider_pkce_ciphertext, authenticated_principal_id, expected_identity_id,
        expected_connection_generation, expected_connection_id, expected_token_version,
        target_connection_id, target_connection_generation, target_token_version,
        device_name, client_kind, created_at, expires_at)
     VALUES (?, 'connect_calendar', 'pending', ?, ?, ?, ?, 1, 1, 'dek', 'wrapped',
             'payload', 'ciphertext', 'principal-a', 'identity-a', ?, ?, ?, ?, ?, ?,
             'Browser', 'web', ?, ?)`,
  )
    .bind(
      id,
      `state-${id}`,
      `nonce-${id}`,
      `poll-${id}`,
      `challenge-${id}`,
      shape === "new" ? 0 : 1,
      shape === "new" ? null : "connection-a",
      shape === "new" ? null : 1,
      shape === "new" ? `connection-${id}` : "connection-a",
      shape === "new" ? 1 : 2,
      shape === "new" ? 1 : 2,
      NOW,
      NOW + 600,
    )
    .run();
}

async function startExchange(id: string): Promise<void> {
  await testEnv.DB.prepare(
    `UPDATE oauth_transactions
     SET status = 'exchanging',
         provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL,
         provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL,
         provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL,
         exchange_started_at = ?, exchange_deadline_at = ?
     WHERE id = ?`,
  )
    .bind(NOW + 1, NOW + 30, id)
    .run();
}

async function epoch(id = "principal-a"): Promise<number | null> {
  return testEnv.DB.prepare("SELECT google_connection_generation FROM principals WHERE id = ?")
    .bind(id)
    .first<number>("google_connection_generation");
}

beforeEach(async () => {
  await testEnv.DB.prepare("DELETE FROM oauth_transactions").run();
  await testEnv.DB.prepare("DELETE FROM principals").run();
  await testEnv.DB.prepare("DELETE FROM identity_deletion_fences").run();
});

describe("initial D1 schema invariants", () => {
  it("bounds and freezes Google identity while leaving metadata mutable", async () => {
    await principal();
    await identity();
    await expect(
      testEnv.DB.prepare(
        "UPDATE external_identities SET id = id, principal_id = principal_id, subject = subject, email = 'new@example.test' WHERE id = 'identity-a'",
      ).run(),
    ).resolves.toMatchObject({ meta: { changes: 1 } });

    for (const subject of [
      "",
      "x".repeat(256),
      "é".repeat(128),
      "nul\u0000control",
      "line\nbreak",
      "del\u007fete",
    ]) {
      await expect(
        identity(`identity-${subject.length}`, "principal-a", subject),
      ).rejects.toThrow();
    }
    for (const [column, value] of [
      ["id", "identity-b"],
      ["principal_id", "principal-b"],
      ["provider", "microsoft"],
      ["issuer", "accounts.google.com"],
      ["subject", "subject-b"],
    ] as const) {
      await expect(
        testEnv.DB.prepare(`UPDATE external_identities SET ${column} = ? WHERE id = 'identity-a'`)
          .bind(value)
          .run(),
      ).rejects.toThrow("external identity is immutable");
    }
  });

  it("advances the principal epoch on insert and delete and rejects stale insertion", async () => {
    await principal();
    await identity();
    await connection();
    expect(await epoch()).toBe(1);
    await expect(connection("stale", "principal-a", "identity-a", 1)).rejects.toThrow(
      "invalid connection insertion authority",
    );
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = 'connection-a'").run();
    expect(await epoch()).toBe(2);
    await expect(connection("still-stale", "principal-a", "identity-a", 2)).rejects.toThrow();
    await connection("connection-new", "principal-a", "identity-a", 3);
    expect(await epoch()).toBe(3);
  });

  it("accepts same-value ownership and coherent lease metadata without token mutation", async () => {
    await principal();
    await identity();
    await connection();
    await expect(
      testEnv.DB.prepare(
        `UPDATE connections
         SET id = id, principal_id = principal_id, identity_id = identity_id, provider = provider,
             refresh_lease_owner = 'worker', refresh_lease_until = ?,
             refresh_lease_generation = generation, refresh_lease_token_version = token_version,
             updated_at = ?
         WHERE id = 'connection-a'`,
      )
        .bind(NOW + 30, NOW + 1)
        .run(),
    ).resolves.toMatchObject({ meta: { changes: 1 } });
    await expect(
      testEnv.DB.prepare(
        "UPDATE connections SET principal_id = 'other' WHERE id = 'connection-a'",
      ).run(),
    ).rejects.toThrow("connection ownership is immutable");
    await expect(
      testEnv.DB.prepare(
        "UPDATE connections SET refresh_lease_generation = 2 WHERE id = 'connection-a'",
      ).run(),
    ).rejects.toThrow();
  });

  it("rejects arbitrary jumps and envelope replacement without the exact version transition", async () => {
    await principal();
    await identity();
    await connection();
    for (const sql of [
      "UPDATE connections SET generation = 3, token_version = 3, dek_iv = 'd', wrapped_dek = 'w', payload_iv = 'p', ciphertext = 'c', updated_at = ? WHERE id = 'connection-a'",
      "UPDATE connections SET token_version = 3, dek_iv = 'd', wrapped_dek = 'w', payload_iv = 'p', ciphertext = 'c', updated_at = ? WHERE id = 'connection-a'",
      "UPDATE connections SET ciphertext = 'swapped', updated_at = ? WHERE id = 'connection-a'",
      "UPDATE connections SET token_version = 2, updated_at = ? WHERE id = 'connection-a'",
    ]) {
      await expect(
        testEnv.DB.prepare(sql)
          .bind(NOW + 1)
          .run(),
      ).rejects.toThrow("invalid connection authority transition");
    }
  });

  it("permits exact refresh and KEK rewrap transitions", async () => {
    await principal();
    await identity();
    await connection();
    await testEnv.DB.prepare(
      `UPDATE connections
       SET token_version = 2, key_version = 2, dek_iv = 'dek-2', wrapped_dek = 'wrapped-2',
           payload_iv = 'payload-2', ciphertext = 'ciphertext-2', updated_at = ?
       WHERE id = 'connection-a'`,
    )
      .bind(NOW + 1)
      .run();
    expect(await epoch()).toBe(1);
    await testEnv.DB.prepare(
      `UPDATE connections
       SET key_version = 3, dek_iv = 'dek-3', wrapped_dek = 'wrapped-3', updated_at = ?
       WHERE id = 'connection-a'`,
    )
      .bind(NOW + 2)
      .run();
    await expect(
      testEnv.DB.prepare(
        "SELECT generation, token_version, key_version, payload_iv, ciphertext FROM connections WHERE id = 'connection-a'",
      ).first(),
    ).resolves.toEqual({
      generation: 1,
      token_version: 2,
      key_version: 3,
      payload_iv: "payload-2",
      ciphertext: "ciphertext-2",
    });
  });

  it("requires OAuth replacement to reactivate and advances the authority epoch", async () => {
    await principal();
    await identity();
    await connection();
    await testEnv.DB.prepare(
      "UPDATE connections SET status = 'reconnect_required', updated_at = ? WHERE id = 'connection-a'",
    )
      .bind(NOW + 1)
      .run();
    await expect(
      testEnv.DB.prepare(
        "UPDATE connections SET status = 'active', updated_at = ? WHERE id = 'connection-a'",
      )
        .bind(NOW + 2)
        .run(),
    ).rejects.toThrow("invalid connection authority transition");
    await testEnv.DB.prepare(
      `UPDATE connections
       SET status = 'active', generation = 2, token_version = 2,
           dek_iv = 'oauth-dek', wrapped_dek = 'oauth-wrapped',
           payload_iv = 'oauth-payload', ciphertext = 'oauth-ciphertext', updated_at = ?
       WHERE id = 'connection-a'`,
    )
      .bind(NOW + 2)
      .run();
    expect(await epoch()).toBe(2);
  });

  it("constrains sign-in and both connect snapshot shapes", async () => {
    await principal();
    await identity();
    await pendingSignIn("sign-in");
    await pendingConnect("new-connect");
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO oauth_transactions
           (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
            tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
            provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
            provider_pkce_ciphertext, authenticated_principal_id, expected_identity_id,
            expected_connection_generation, target_connection_id, target_connection_generation,
            target_token_version, device_name, client_kind, created_at, expires_at)
         VALUES ('bad-shape', 'connect_calendar', 'pending', 'bad-state', 'n', 'p', 'c',
                 1, 1, 'd', 'w', 'p', 'c', 'principal-a', 'identity-a', 0,
                 'target', 2, 1, 'Browser', 'web', ?, ?)`,
      )
        .bind(NOW, NOW + 600)
        .run(),
    ).rejects.toThrow();

    await testEnv.DB.prepare(
      "UPDATE oauth_transactions SET status = 'failed', provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL, provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL, provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL, failure_code = 'access_denied', callback_completed_at = ? WHERE id = 'new-connect'",
    )
      .bind(NOW + 1)
      .run();
    await connection();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO oauth_transactions
           (id, intent, status, state_hash, nonce_hash, polling_secret_hash,
            tasknotes_pkce_challenge, provider_pkce_schema_version, provider_pkce_key_version,
            provider_pkce_dek_iv, provider_pkce_wrapped_dek, provider_pkce_payload_iv,
            provider_pkce_ciphertext, authenticated_principal_id, expected_identity_id,
            expected_connection_generation, expected_connection_id, expected_token_version,
            target_connection_id, target_connection_generation, target_token_version,
            device_name, client_kind, created_at, expires_at)
         VALUES ('stale-connect', 'connect_calendar', 'pending', 'stale-state', 'n', 'p', 'c',
                 1, 1, 'd', 'w', 'p', 'c', 'principal-a', 'identity-a', 0,
                 'connection-a', 1, 'connection-a', 1, 2, 'Browser', 'web', ?, ?)`,
      )
        .bind(NOW, NOW + 600)
        .run(),
    ).rejects.toThrow("invalid connect transaction snapshot");
    await pendingConnect("existing-connect", "existing");
  });

  it("allows only one pending or exchanging connect transaction per principal", async () => {
    await principal();
    await identity();
    await pendingConnect("connect-a");
    await expect(pendingConnect("connect-b")).rejects.toThrow();
    await startExchange("connect-a");
    await expect(pendingConnect("connect-c")).rejects.toThrow();
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions
       SET status = 'failed', failure_code = 'authorization_failed', callback_completed_at = ?
       WHERE id = 'connect-a'`,
    )
      .bind(NOW + 31)
      .run();
    await pendingConnect("connect-d");
  });

  it("erases the complete provider-PKCE envelope once and rejects substitution or partial erasure", async () => {
    await pendingSignIn("pkce");
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET provider_pkce_ciphertext = 'substitute' WHERE id = 'pkce'",
      ).run(),
    ).rejects.toThrow("oauth transaction binding is immutable");
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET provider_pkce_ciphertext = NULL WHERE id = 'pkce'",
      ).run(),
    ).rejects.toThrow();
    await startExchange("pkce");
    await expect(
      testEnv.DB.prepare("UPDATE oauth_transactions SET exchange_deadline_at = ? WHERE id = 'pkce'")
        .bind(NOW + 31)
        .run(),
    ).rejects.toThrow("oauth transaction binding is immutable");
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET provider_pkce_ciphertext = 'restored' WHERE id = 'pkce'",
      ).run(),
    ).rejects.toThrow("oauth transaction binding is immutable");
  });

  it("accepts every legal OAuth edge and rejects terminal exits", async () => {
    await principal();
    await identity();

    await pendingSignIn("authorized-path");
    await startExchange("authorized-path");
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions
       SET status = 'authorized', authorized_principal_id = 'principal-a',
           authorized_identity_id = 'identity-a', callback_completed_at = ?
       WHERE id = 'authorized-path'`,
    )
      .bind(NOW + 40)
      .run();
    await testEnv.DB.prepare(
      "UPDATE oauth_transactions SET status = 'consumed', consumed_at = ? WHERE id = 'authorized-path'",
    )
      .bind(NOW + 41)
      .run();
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET status = 'expired' WHERE id = 'authorized-path'",
      ).run(),
    ).rejects.toThrow("illegal oauth transaction transition");

    await pendingSignIn("pending-failed");
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions SET status = 'failed', failure_code = 'access_denied',
       callback_completed_at = ?, provider_pkce_schema_version = NULL,
       provider_pkce_key_version = NULL, provider_pkce_dek_iv = NULL,
       provider_pkce_wrapped_dek = NULL, provider_pkce_payload_iv = NULL,
       provider_pkce_ciphertext = NULL WHERE id = 'pending-failed'`,
    )
      .bind(NOW + 601)
      .run();
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET status = 'pending' WHERE id = 'pending-failed'",
      ).run(),
    ).rejects.toThrow("illegal oauth transaction transition");

    await pendingSignIn("exchange-failed");
    await startExchange("exchange-failed");
    await testEnv.DB.prepare(
      "UPDATE oauth_transactions SET status = 'failed', failure_code = 'identity_mismatch', callback_completed_at = ? WHERE id = 'exchange-failed'",
    )
      .bind(NOW + 601)
      .run();
  });

  it("terminalizes pending, exchanging, and authorized transactions as expired with authority cleared", async () => {
    await principal();
    await identity();
    await pendingSignIn("pending-expired");
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions SET status = 'expired', provider_pkce_schema_version = NULL,
       provider_pkce_key_version = NULL, provider_pkce_dek_iv = NULL,
       provider_pkce_wrapped_dek = NULL, provider_pkce_payload_iv = NULL,
       provider_pkce_ciphertext = NULL WHERE id = 'pending-expired'`,
    ).run();

    await pendingSignIn("exchange-expired");
    await startExchange("exchange-expired");
    await testEnv.DB.prepare(
      "UPDATE oauth_transactions SET status = 'expired' WHERE id = 'exchange-expired'",
    ).run();

    await pendingSignIn("authorized-expired");
    await startExchange("authorized-expired");
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions SET status = 'authorized',
       authorized_principal_id = 'principal-a', authorized_identity_id = 'identity-a',
       callback_completed_at = ? WHERE id = 'authorized-expired'`,
    )
      .bind(NOW + 40)
      .run();
    await testEnv.DB.prepare(
      `UPDATE oauth_transactions SET status = 'expired', authorized_principal_id = NULL,
       authorized_identity_id = NULL, authorized_connection_id = NULL,
       callback_completed_at = NULL WHERE id = 'authorized-expired'`,
    ).run();
    const rows = await testEnv.DB.prepare(
      `SELECT status, authorized_principal_id, provider_pkce_ciphertext
       FROM oauth_transactions
       WHERE id IN ('pending-expired', 'exchange-expired', 'authorized-expired')
       ORDER BY id`,
    ).all();
    expect(rows.results).toEqual([
      { status: "expired", authorized_principal_id: null, provider_pkce_ciphertext: null },
      { status: "expired", authorized_principal_id: null, provider_pkce_ciphertext: null },
      { status: "expired", authorized_principal_id: null, provider_pkce_ciphertext: null },
    ]);
  });

  it("freezes OAuth locator, client, and authority snapshots on actual changes", async () => {
    await principal();
    await identity();
    await pendingConnect("immutable");
    const changes = [
      ["id", "other"],
      ["intent", "sign_in"],
      ["state_hash", "other-state"],
      ["nonce_hash", "other-nonce"],
      ["polling_secret_hash", "other-poll"],
      ["tasknotes_pkce_challenge", "other-challenge"],
      ["authenticated_principal_id", null],
      ["expected_identity_id", null],
      ["expected_connection_generation", 1],
      ["expected_connection_id", "other"],
      ["expected_token_version", 1],
      ["target_connection_id", "other"],
      ["target_connection_generation", 2],
      ["target_token_version", 2],
      ["device_name", "Phone"],
      ["client_kind", "ios"],
      ["created_at", NOW + 1],
      ["expires_at", NOW + 601],
    ] as const;
    for (const [column, value] of changes) {
      await expect(
        testEnv.DB.prepare(`UPDATE oauth_transactions SET ${column} = ? WHERE id = 'immutable'`)
          .bind(value)
          .run(),
      ).rejects.toThrow("oauth transaction binding is immutable");
    }
    await expect(
      testEnv.DB.prepare(
        "UPDATE oauth_transactions SET id = id, intent = intent, expires_at = expires_at WHERE id = 'immutable'",
      ).run(),
    ).resolves.toMatchObject({ meta: { changes: 1 } });
  });

  it("retains the redemption FK, uniqueness, and ON DELETE SET NULL behavior", async () => {
    await principal();
    await pendingSignIn("redemption");
    await testEnv.DB.prepare(
      `INSERT INTO device_sessions
       (id, principal_id, credential_hash, device_name, client_kind, created_at,
        last_used_at, idle_expires_at, absolute_expires_at, redemption_transaction_id)
       VALUES ('session-a', 'principal-a', 'digest-a', 'Browser', 'web', ?, ?, ?, ?, 'redemption')`,
    )
      .bind(NOW, NOW, NOW + 100, NOW + 200)
      .run();
    await expect(
      testEnv.DB.prepare(
        `INSERT INTO device_sessions
         (id, principal_id, credential_hash, device_name, client_kind, created_at,
          last_used_at, idle_expires_at, absolute_expires_at, redemption_transaction_id)
         VALUES ('session-b', 'principal-a', 'digest-b', 'Phone', 'ios', ?, ?, ?, ?, 'redemption')`,
      )
        .bind(NOW, NOW, NOW + 100, NOW + 200)
        .run(),
    ).rejects.toThrow();
    await testEnv.DB.prepare("DELETE FROM oauth_transactions WHERE id = 'redemption'").run();
    await expect(
      testEnv.DB.prepare(
        "SELECT redemption_transaction_id FROM device_sessions WHERE id = 'session-a'",
      ).first("redemption_transaction_id"),
    ).resolves.toBeNull();
    expect((await testEnv.DB.prepare("PRAGMA foreign_key_check").all()).results).toEqual([]);
  });
});
