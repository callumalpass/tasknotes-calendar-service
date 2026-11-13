import { env } from "cloudflare:workers";
import { createScheduledController } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import type { Env } from "../../src/env";
import { createWorker } from "../../src/index";

const bindings = env as unknown as Env;
const db = bindings.DB;

function cleanup(): Promise<void> {
  return createWorker().scheduled(
    createScheduledController({ cron: "0 * * * *", scheduledTime: 0 }),
    bindings,
  );
}

async function pending(id: string, expiresIn: number): Promise<void> {
  await db
    .prepare(
      `INSERT INTO oauth_transactions
    (id, intent, status, state_hash, nonce_hash, polling_secret_hash, tasknotes_pkce_challenge,
     provider_pkce_schema_version, provider_pkce_key_version, provider_pkce_dek_iv,
     provider_pkce_wrapped_dek, provider_pkce_payload_iv, provider_pkce_ciphertext,
     device_name, client_kind, created_at, expires_at)
    VALUES (?, 'sign_in', 'pending', ?, 'nonce', 'poll', 'challenge',
      1, 1, 'dek', 'wrapped', 'iv', 'ciphertext', 'Browser', 'web', unixepoch() + ? - 600, unixepoch() + ?)`,
    )
    .bind(id, `state-${id}`, expiresIn, expiresIn)
    .run();
}

async function transition(id: string, status: string): Promise<void> {
  await db
    .prepare(
      `UPDATE oauth_transactions SET status = ?,
    provider_pkce_schema_version = NULL, provider_pkce_key_version = NULL,
    provider_pkce_dek_iv = NULL, provider_pkce_wrapped_dek = NULL,
    provider_pkce_payload_iv = NULL, provider_pkce_ciphertext = NULL,
    exchange_started_at = CASE WHEN ? = 'exchanging' THEN created_at + 1 ELSE NULL END,
    exchange_deadline_at = CASE WHEN ? = 'exchanging' THEN created_at + 120 ELSE NULL END,
    failure_code = CASE WHEN ? = 'failed' THEN 'access_denied' ELSE NULL END,
    callback_completed_at = CASE WHEN ? = 'failed' THEN created_at + 2 ELSE NULL END
    WHERE id = ?`,
    )
    .bind(status, status, status, status, status, id)
    .run();
}

beforeEach(async () => {
  await db.batch([
    db.prepare("DELETE FROM oauth_transactions"),
    db.prepare("DELETE FROM principals"),
    db.prepare("DELETE FROM identity_deletion_fences"),
    db.prepare("INSERT INTO principals (id, created_at, last_active_at) VALUES ('retained', 0, 0)"),
    db.prepare(`INSERT INTO external_identities
      (id, principal_id, provider, issuer, subject, email_verified, created_at, updated_at)
      VALUES ('identity', 'retained', 'google', 'https://accounts.google.com', 'subject', 1, 0, 0)`),
  ]);
});

describe("hourly D1 retention", () => {
  it("deletes expired transactions in every status without revoking a live redeemed session", async () => {
    for (const status of ["pending", "exchanging", "failed", "expired", "authorized", "consumed"]) {
      await pending(status, -10);
      if (status === "pending") continue;
      if (status === "failed" || status === "expired") {
        await transition(status, status);
      } else {
        await transition(status, "exchanging");
        if (status === "exchanging") continue;
        await db
          .prepare(
            `UPDATE oauth_transactions SET status = 'authorized',
          authorized_principal_id = 'retained', authorized_identity_id = 'identity',
          callback_completed_at = created_at + 2 WHERE id = ?`,
          )
          .bind(status)
          .run();
        if (status === "consumed") {
          await db
            .prepare(
              `UPDATE oauth_transactions SET status = 'consumed',
            consumed_at = created_at + 3 WHERE id = ?`,
            )
            .bind(status)
            .run();
        }
      }
    }
    await pending("live", 600);
    await db
      .prepare(
        `INSERT INTO device_sessions
      (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at,
       idle_expires_at, absolute_expires_at, redemption_transaction_id)
      VALUES ('live-session', 'retained', 'digest', 'Browser', 'web', 0, 0,
        unixepoch() + 600, unixepoch() + 1200, 'consumed')`,
      )
      .run();

    await cleanup();

    expect(
      (await db.prepare("SELECT id FROM oauth_transactions ORDER BY id").all()).results,
    ).toEqual([{ id: "live" }]);
    expect(
      await db.prepare("SELECT redemption_transaction_id FROM device_sessions").first(),
    ).toEqual({ redemption_transaction_id: null });
    expect(await db.prepare("SELECT id FROM principals").first()).toEqual({ id: "retained" });
  });

  it("deletes revoked and expired sessions and old fences, preserving live authority", async () => {
    for (const [id, idle, absolute, revoked] of [
      ["live", 600, 600, null],
      ["revoked", 600, 1200, 1],
      ["idle", -1, 1200, null],
    ] as const) {
      await db
        .prepare(
          `INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at,
         idle_expires_at, absolute_expires_at, revoked_at)
        VALUES (?, 'retained', ?, 'Browser', 'web', 0, 0, unixepoch() + ?, unixepoch() + ?, ?)`,
        )
        .bind(id, `digest-${id}`, idle, absolute, revoked)
        .run();
    }
    await db.batch([
      db.prepare("INSERT INTO identity_deletion_fences VALUES ('old', unixepoch() - 3601)"),
      db.prepare("INSERT INTO identity_deletion_fences VALUES ('recent', unixepoch() - 3590)"),
    ]);
    await cleanup();
    expect((await db.prepare("SELECT id FROM device_sessions").all()).results).toEqual([
      { id: "live" },
    ]);
    expect(
      (await db.prepare("SELECT identity_digest FROM identity_deletion_fences").all()).results,
    ).toEqual([{ identity_digest: "recent" }]);
  });

  it("bounds each table to 100 deletions per run and drains on the next run", async () => {
    for (let index = 0; index < 103; index += 1) await pending(`expired-${index}`, -1);
    await db.batch([
      db.prepare(`INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at,
         idle_expires_at, absolute_expires_at)
        SELECT id, 'retained', id, 'Browser', 'web', 0, 0, 1, 2 FROM oauth_transactions`),
      db.prepare(`INSERT INTO identity_deletion_fences
        SELECT id, unixepoch() - 3601 FROM oauth_transactions`),
    ]);
    await cleanup();
    for (const table of ["oauth_transactions", "device_sessions", "identity_deletion_fences"]) {
      expect(await db.prepare(`SELECT count(*) AS count FROM ${table}`).first()).toEqual({
        count: 3,
      });
    }
    await Promise.all([cleanup(), cleanup()]);
    for (const table of ["oauth_transactions", "device_sessions", "identity_deletion_fences"]) {
      expect(await db.prepare(`SELECT count(*) AS count FROM ${table}`).first()).toEqual({
        count: 0,
      });
    }
  });

  it("surfaces cleanup failures and rolls the batch back atomically", async () => {
    await pending("expired", -1);
    await db.batch([
      db.prepare(`INSERT INTO device_sessions
        (id, principal_id, credential_hash, device_name, client_kind, created_at, last_used_at,
         idle_expires_at, absolute_expires_at)
        VALUES ('expired', 'retained', 'digest', 'Browser', 'web', 0, 0, 1, 2)`),
      db.prepare("INSERT INTO identity_deletion_fences VALUES ('old', 0)"),
      db.prepare(`CREATE TRIGGER retention_fault BEFORE DELETE ON device_sessions
        BEGIN SELECT RAISE(ABORT, 'injected retention failure'); END`),
    ]);
    try {
      await expect(cleanup()).rejects.toThrow();
      for (const table of ["oauth_transactions", "device_sessions", "identity_deletion_fences"]) {
        expect(await db.prepare(`SELECT count(*) AS count FROM ${table}`).first()).toEqual({
          count: 1,
        });
      }
    } finally {
      await db.prepare("DROP TRIGGER retention_fault").run();
    }
  });
});
