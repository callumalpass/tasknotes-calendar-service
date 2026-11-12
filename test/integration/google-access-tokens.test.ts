/* eslint-disable @typescript-eslint/no-non-null-assertion, @typescript-eslint/require-await */
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  GoogleAccessTokenError,
  GoogleAccessTokens,
  type GoogleAccessTokensDependencies,
} from "../../src/connections/google-access-tokens";
import {
  decryptTokenEnvelope,
  encryptTokenEnvelope,
  type TokenPayload,
} from "../../src/crypto/token-envelope";
import { googleTestConfiguration, type GoogleTokenRefresh } from "../../src/provider/google";
import type { ProviderOutcome } from "../../src/provider/types";
import {
  tokenEnvelopeFromRow,
  tokenEnvelopeToRow,
  type TokenEnvelopeRow,
} from "../../src/storage/token-envelope-row";
import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const IDENTITY = "22222222-2222-4222-8222-222222222222";
const CONNECTION = "33333333-3333-4333-8333-333333333333";
const NOW = 1_788_048_000;
let databaseNow: number;
const SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
  "profile",
  "https://www.googleapis.com/auth/calendar.events",
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
] as const;
const keyring = { activeVersion: 1, keys: new Map([[1, new Uint8Array(32).fill(2)]]) };

function sequentialRandom() {
  let value = 0;
  return {
    bytes(length: number): Uint8Array {
      value = (value + 1) & 255;
      return new Uint8Array(length).fill(value);
    },
  };
}

async function seed(payload: TokenPayload, environment = "local"): Promise<void> {
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(PRINCIPAL, NOW, NOW)
    .run();
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
      (id, principal_id, provider, issuer, subject, email, display_name, email_verified,
       created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', 'subject', NULL, NULL, 1, ?, ?)`,
  )
    .bind(IDENTITY, PRINCIPAL, NOW, NOW)
    .run();
  const value = await encryptTokenEnvelope(
    payload,
    {
      environment,
      provider: "google",
      principalId: PRINCIPAL,
      connectionId: CONNECTION,
      connectionGeneration: 1,
      tokenVersion: 1,
      tokenKind: "calendar_oauth",
    },
    keyring,
    sequentialRandom(),
  );
  const row = tokenEnvelopeToRow(value);
  await testEnv.DB.prepare(
    `INSERT INTO connections
      (id, principal_id, identity_id, provider, status, generation,
       envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
       token_version, created_at, updated_at)
     VALUES (?, ?, ?, 'google', 'active', 1, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
  )
    .bind(
      CONNECTION,
      PRINCIPAL,
      IDENTITY,
      row.envelope_schema_version,
      row.key_version,
      row.dek_iv,
      row.wrapped_dek,
      row.payload_iv,
      row.ciphertext,
      NOW,
      NOW,
    )
    .run();
}

type TestOverrides = Partial<GoogleAccessTokensDependencies> & {
  readonly refreshGoogleToken?: () => Promise<ProviderOutcome<GoogleTokenRefresh>>;
};

function providerResponse(outcome: ProviderOutcome<GoogleTokenRefresh>): Response {
  if (outcome.ok) {
    return Response.json({
      access_token: outcome.value.accessToken,
      token_type: "Bearer",
      expires_in: outcome.value.expiresInSeconds,
      ...(outcome.value.scope === undefined ? {} : { scope: outcome.value.scope }),
      ...(outcome.value.refreshToken === undefined
        ? {}
        : { refresh_token: outcome.value.refreshToken }),
    });
  }
  if (outcome.error.code === "reauthorization_required") {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }
  const status = outcome.error.code === "rate_limited" ? 429 : 503;
  return Response.json(
    { error: "generic" },
    {
      status,
      ...(outcome.error.retryAfterSeconds === undefined
        ? {}
        : { headers: { "retry-after": String(outcome.error.retryAfterSeconds) } }),
    },
  );
}

function databaseWithAcquireFault(): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") {
          return (...values: unknown[]) => wrap(target.bind(...values));
        }
        if (property === "first") {
          return async () => {
            throw new Error("ambiguous acquisition");
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  return new Proxy<D1Database>(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (query: string) => {
          const statement = target.prepare(query);
          return query.includes("UPDATE connections SET refresh_lease_owner = ?")
            ? wrap(statement)
            : statement;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function service(overrides: TestOverrides = {}): GoogleAccessTokens {
  const { refreshGoogleToken: refresh, ...dependencies } = overrides;
  return new GoogleAccessTokens({
    db: testEnv.DB,
    environment: "local",
    googleClientId: "client",
    googleClientSecret: "secret",
    tokenKeyring: keyring,
    googleProvider: googleTestConfiguration({
      tokenEndpoint: "http://127.0.0.1:9797/token",
      revocationEndpoint: "http://127.0.0.1:9797/revoke",
      calendarApiOrigin: "http://127.0.0.1:9797",
    }),
    fetch: async () =>
      providerResponse(
        await (
          refresh ??
          (async () => ({
            ok: true as const,
            value: { accessToken: "new-access", expiresInSeconds: 3_600 },
          }))
        )(),
      ),
    random: sequentialRandom(),
    sleep: async () => Promise.resolve(),
    ...dependencies,
  });
}

function payload(expiresAtEpochSeconds: number): TokenPayload {
  return {
    accessToken: "old-access-canary",
    refreshToken: "refresh-canary",
    expiresAtEpochSeconds,
    scopes: SCOPES,
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "GoogleAccessTokenError",
    code,
    message: "Google access token operation failed.",
  });
}

describe("GoogleAccessTokens with real D1", () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
    await testEnv.DB.prepare("DELETE FROM principals").run();
    const current = await testEnv.DB.prepare("SELECT unixepoch() AS now").first<number>("now");
    if (current === null) throw new Error("missing D1 clock");
    databaseNow = current;
  });

  it("loads only the principal-scoped joined epoch and returns immutable fresh grants", async () => {
    await seed(payload(databaseNow + 61));
    const tokens = service();
    const snapshot = await tokens.loadForPrincipal(PRINCIPAL);
    expect(snapshot).toEqual({
      principalId: PRINCIPAL,
      connectionId: CONNECTION,
      generation: 1,
      tokenVersion: 1,
      principalGeneration: 1,
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    const grant = await tokens.access(snapshot!);
    expect(grant.accessToken).toBe("old-access-canary");
    expect(Object.isFrozen(grant)).toBe(true);
    await expect(tokens.assertCurrent(grant)).resolves.toBeUndefined();
    await expect(
      tokens.loadForPrincipal("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ).rejects.toBeInstanceOf(GoogleAccessTokenError);
  });

  it("answers a fresh grant from the clock the snapshot was read under", async () => {
    await seed(payload(databaseNow + 90));
    const queries: string[] = [];
    const db = new Proxy<D1Database>(testEnv.DB, {
      get(target, property): unknown {
        if (property === "prepare") {
          return (query: string) => {
            queries.push(query);
            return target.prepare(query);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
    const tokens = service({ db });
    const snapshot = await tokens.loadForPrincipal(PRINCIPAL);
    expect(queries).toHaveLength(1);
    expect((await tokens.access(snapshot!)).accessToken).toBe("old-access-canary");
    expect(queries).toHaveLength(1);
  });

  it.each([-60, 60])(
    "uses D1 freshness with an isolate clock skew of %s seconds",
    async (isolateSkew) => {
      await seed(payload(databaseNow + 90));
      vi.spyOn(Date, "now").mockReturnValue((databaseNow + isolateSkew) * 1_000);
      const refresh = vi.fn();
      const tokens = service({ refreshGoogleToken: refresh });
      const grant = await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
      expect(grant.accessToken).toBe("old-access-canary");
      expect(refresh).not.toHaveBeenCalled();
    },
  );

  it.each([-60, 60])(
    "uses D1 for refreshed expiry commits with an isolate clock skew of %s seconds",
    async (isolateSkew) => {
      await seed(payload(databaseNow));
      vi.spyOn(Date, "now").mockReturnValue((databaseNow + isolateSkew) * 1_000);
      const tokens = service({
        refreshGoogleToken: async () => ({
          ok: true,
          value: { accessToken: "db-timed-access", expiresInSeconds: 600 },
        }),
      });
      await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
      const persisted = await testEnv.DB.prepare("SELECT * FROM connections").first();
      if (persisted === null) throw new Error("missing refreshed connection");
      const decrypted = await decryptTokenEnvelope(
        tokenEnvelopeFromRow(persisted as unknown as TokenEnvelopeRow),
        {
          environment: "local",
          provider: "google",
          principalId: PRINCIPAL,
          connectionId: CONNECTION,
          connectionGeneration: 1,
          tokenVersion: 2,
          tokenKind: "calendar_oauth",
        },
        keyring,
      );
      expect(decrypted.expiresAtEpochSeconds).toBe(
        Number(persisted["last_provider_success_at"]) + 600,
      );
    },
  );

  it("refreshes at skew equality and forceRefresh bypasses freshness once", async () => {
    await seed(payload(databaseNow + 60));
    const refresh = vi.fn(async () => ({
      ok: true as const,
      value: { accessToken: "refreshed", expiresInSeconds: 3_600 },
    }));
    const tokens = service({ refreshGoogleToken: refresh });
    const first = await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
    expect(first).toMatchObject({ accessToken: "refreshed", tokenVersion: 2 });
    expect(refresh).toHaveBeenCalledTimes(1);

    const current = await tokens.loadForPrincipal(PRINCIPAL);
    await tokens.access(current!, { forceRefresh: true });
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("serializes twenty expired callers to one provider refresh", async () => {
    await seed(payload(NOW));
    const refresh = vi.fn(async () => {
      await Promise.resolve();
      return {
        ok: true as const,
        value: { accessToken: "winner-access", expiresInSeconds: 3_600 },
      };
    });
    const tokens = service({ refreshGoogleToken: refresh });
    const snapshots = await Promise.all(
      Array.from({ length: 20 }, () => tokens.loadForPrincipal(PRINCIPAL)),
    );
    const grants = await Promise.all(snapshots.map((snapshot) => tokens.access(snapshot!)));
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(new Set(grants.map((grant) => `${grant.accessToken}:${grant.tokenVersion}`))).toEqual(
      new Set(["winner-access:2"]),
    );
  });

  it("preserves omitted material and accepts strict rotated material", async () => {
    await seed(payload(NOW));
    const tokens = service({
      refreshGoogleToken: async () => ({
        ok: true,
        value: {
          accessToken: "rotated-access",
          refreshToken: "rotated-refresh",
          expiresInSeconds: 500,
          scope: SCOPES.join(" "),
        },
      }),
    });
    expect(await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!)).toMatchObject({
      accessToken: "rotated-access",
      tokenVersion: 2,
    });
    expect(
      JSON.stringify(await testEnv.DB.prepare("SELECT * FROM connections").all()),
    ).not.toContain("rotated-access");
    expect(
      JSON.stringify(await testEnv.DB.prepare("SELECT * FROM connections").all()),
    ).not.toContain("rotated-refresh");
    const persisted = await testEnv.DB.prepare("SELECT * FROM connections").first();
    if (persisted === null) throw new Error("missing rotated connection");
    await expect(
      decryptTokenEnvelope(
        tokenEnvelopeFromRow(persisted as unknown as TokenEnvelopeRow),
        {
          environment: "local",
          provider: "google",
          principalId: PRINCIPAL,
          connectionId: CONNECTION,
          connectionGeneration: 1,
          tokenVersion: 2,
          tokenKind: "calendar_oauth",
        },
        keyring,
      ),
    ).resolves.toMatchObject({ refreshToken: "rotated-refresh" });
  });

  it.each([
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "unknown.scope",
  ])("rejects unsafe returned scope %s and retains the attempt lease", async (scope) => {
    await seed(payload(NOW));
    const tokens = service({
      refreshGoogleToken: async () => ({
        ok: true,
        value: { accessToken: "unsafe", expiresInSeconds: 500, scope },
      }),
    });
    await expectCode(tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!), "unavailable");
    expect(
      await testEnv.DB.prepare("SELECT refresh_lease_owner FROM connections").first(
        "refresh_lease_owner",
      ),
    ).toBeNull();
  });

  it("marks exact invalid_grant reconnect and returns only a generic error", async () => {
    await seed(payload(NOW));
    const tokens = service({
      refreshGoogleToken: async () => ({
        ok: false,
        error: { code: "reauthorization_required", message: "invalid_grant refresh-canary" },
      }),
    });
    await expectCode(tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!), "reconnect");
    expect(await testEnv.DB.prepare("SELECT status FROM connections").first()).toEqual({
      status: "reconnect_required",
    });
    await expectCode(tokens.loadForPrincipal(PRINCIPAL), "reconnect");
  });

  it.each([
    [{ code: "rate_limited", message: "secret", retryAfterSeconds: 17 }, "rate_limited", 17],
    [{ code: "timeout", message: "secret" }, "unavailable", undefined],
    [{ code: "network", message: "secret" }, "unavailable", undefined],
    [{ code: "invalid_response", message: "secret" }, "unavailable", undefined],
  ] as const)(
    "maps provider failure without details and releases its lease",
    async (error, code, retry) => {
      await seed(payload(NOW));
      const tokens = service({ refreshGoogleToken: async () => ({ ok: false, error }) });
      const operation = tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
      await expect(operation).rejects.toMatchObject({ code, retryAfterSeconds: retry });
      expect(
        await testEnv.DB.prepare("SELECT refresh_lease_owner FROM connections").first(
          "refresh_lease_owner",
        ),
      ).toBeNull();
    },
  );

  it("accepts benign token refresh but rejects disconnect, clones, and forgeries in assertCurrent", async () => {
    await seed(payload(databaseNow + 1_000));
    const tokens = service();
    const grant = await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
    await expectCode(tokens.assertCurrent({ ...grant }), "internal");
    await expectCode(
      tokens.assertCurrent({
        ...grant,
        accessToken: "forged-access",
      }),
      "internal",
    );
    await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!, { forceRefresh: true });
    await expect(tokens.assertCurrent(grant)).resolves.toBeUndefined();
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    await expectCode(tokens.assertCurrent(grant), "conflict");
  });

  it("steals an expired blocked lease and fences its old owner", async () => {
    await seed(payload(databaseNow));
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const refresh = vi.fn(async () => {
      entered();
      if (refresh.mock.calls.length === 1) await blocked;
      return {
        ok: true as const,
        value: { accessToken: "late-access", expiresInSeconds: 500 },
      };
    });
    const owner = service({ refreshGoogleToken: refresh });
    const ownerOperation = owner.access((await owner.loadForPrincipal(PRINCIPAL))!);
    await started;

    // Fault-inject the passage of the full lease while the provider request remains blocked.
    const trigger = await testEnv.DB.prepare(
      "SELECT sql FROM sqlite_master WHERE name = 'connections_validate_update'",
    ).first<string>("sql");
    await testEnv.DB.prepare("DROP TRIGGER connections_validate_update").run();
    await testEnv.DB.prepare(
      "UPDATE connections SET refresh_lease_until = unixepoch() - 1 WHERE id = ?",
    )
      .bind(CONNECTION)
      .run();
    await testEnv.DB.prepare(trigger!).run();
    const contender = service({
      refreshGoogleToken: refresh,
      random: { bytes: (length) => new Uint8Array(length).fill(99) },
    });
    await expect(
      contender.access((await contender.loadForPrincipal(PRINCIPAL))!),
    ).resolves.toMatchObject({ tokenVersion: 2 });
    expect(refresh).toHaveBeenCalledTimes(2);
    release();
    await expect(ownerOperation).resolves.toMatchObject({ tokenVersion: 2 });
    await expect(
      testEnv.DB.prepare(
        `SELECT status, refresh_lease_owner, discovery_lease_owner FROM connections WHERE id = ?`,
      )
        .bind(CONNECTION)
        .first(),
    ).resolves.toEqual({
      status: "active",
      refresh_lease_owner: null,
      discovery_lease_owner: null,
    });
  });

  it("fails an ambiguous acquisition with an expired exact lease before provider work", async () => {
    await seed(payload(databaseNow));
    await testEnv.DB.prepare(
      `UPDATE connections SET refresh_lease_owner = 'stale-attempt', refresh_lease_until = ?,
         refresh_lease_generation = generation, refresh_lease_token_version = token_version,
         updated_at = ? WHERE id = ?`,
    )
      .bind(databaseNow, databaseNow - 120, CONNECTION)
      .run();
    const refresh = vi.fn();
    const tokens = service({ db: databaseWithAcquireFault(), refreshGoogleToken: refresh });
    await expectCode(tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!), "unavailable");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("does not treat a colliding random owner as lease authority", async () => {
    await seed(payload(NOW));
    const collidingOwner = "AQEBAQEBAQEBAQEBAQEBAQ";
    await testEnv.DB.prepare(
      `UPDATE connections SET refresh_lease_owner = ?, refresh_lease_until = ?,
         refresh_lease_generation = 1, refresh_lease_token_version = 1, updated_at = ?
       WHERE id = ?`,
    )
      .bind(collidingOwner, NOW + 30, NOW, CONNECTION)
      .run();
    const refresh = vi.fn(async () => ({
      ok: true as const,
      value: { accessToken: "must-not-run", expiresInSeconds: 500 },
    }));
    const tokens = service({ refreshGoogleToken: refresh });
    await expectCode(tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!), "internal");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("disconnect during the provider request blocks stale commit", async () => {
    await seed(payload(NOW));
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const tokens = service({
      refreshGoogleToken: async () => {
        entered();
        await blocked;
        return {
          ok: true,
          value: { accessToken: "discarded-provider-token", expiresInSeconds: 500 },
        };
      },
    });
    const operation = tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
    await started;
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    release();
    await expectCode(operation, "conflict");
  });

  it("fails closed for exact-AAD mismatch, corrupt scopes, and random failures", async () => {
    await seed(payload(databaseNow + 1_000), "lab");
    await expectCode(service().loadForPrincipal(PRINCIPAL), "internal");

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed({ ...payload(databaseNow), scopes: ["openid", "email", "profile", "unknown"] });
    await expectCode(service().loadForPrincipal(PRINCIPAL), "internal");

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed(payload(databaseNow));
    const randomFailure = service({
      random: {
        bytes: () => {
          throw new Error("random-canary");
        },
      },
    });
    await expectCode(
      randomFailure.access((await randomFailure.loadForPrincipal(PRINCIPAL))!),
      "internal",
    );
  });
});
