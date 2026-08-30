/* eslint-disable @typescript-eslint/no-non-null-assertion, @typescript-eslint/require-await */
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  GoogleAccessTokenError,
  GoogleAccessTokens,
  type GoogleAccessTokensDependencies,
} from "../../src/connections/google-access-tokens";
import { encryptTokenEnvelope, type TokenPayload } from "../../src/crypto/token-envelope";
import { googleTestConfiguration, type GoogleTokenRefresh } from "../../src/provider/google";
import type { ProviderOutcome } from "../../src/provider/types";
import { tokenEnvelopeToRow } from "../../src/storage/token-envelope-row";
import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const IDENTITY = "22222222-2222-4222-8222-222222222222";
const CONNECTION = "33333333-3333-4333-8333-333333333333";
const NOW = 1_788_048_000;
const SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
  "profile",
  "https://www.googleapis.com/auth/calendar.readonly",
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
    nowEpochSeconds: () => NOW,
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
  });

  it("loads only the principal-scoped joined epoch and returns immutable fresh grants", async () => {
    await seed(payload(NOW + 61));
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

  it("refreshes at skew equality and forceRefresh bypasses freshness once", async () => {
    await seed(payload(NOW + 60));
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
  });

  it.each([
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "unknown.scope",
  ])("rejects unsafe returned scope %s and releases the lease", async (scope) => {
    await seed(payload(NOW));
    const tokens = service({
      refreshGoogleToken: async () => ({
        ok: true,
        value: { accessToken: "unsafe", expiresInSeconds: 500, scope },
      }),
    });
    await expectCode(tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!), "internal");
    expect(await testEnv.DB.prepare("SELECT refresh_lease_owner FROM connections").first()).toEqual(
      { refresh_lease_owner: null },
    );
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
        await testEnv.DB.prepare("SELECT refresh_lease_owner FROM connections").first(),
      ).toEqual({
        refresh_lease_owner: null,
      });
    },
  );

  it("rejects disconnect and token-version races in assertCurrent", async () => {
    await seed(payload(NOW + 1_000));
    const tokens = service();
    const grant = await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!);
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    await expectCode(tokens.assertCurrent(grant), "conflict");
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

  it("fails closed for exact-AAD mismatch, corrupt scopes, random and clock failures", async () => {
    await seed(payload(NOW + 1_000), "lab");
    await expectCode(service().loadForPrincipal(PRINCIPAL), "internal");

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed({ ...payload(NOW), scopes: ["openid", "email", "profile", "unknown"] });
    await expectCode(service().loadForPrincipal(PRINCIPAL), "internal");

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed(payload(NOW));
    const clockFailure = service({
      nowEpochSeconds: () => {
        throw new Error("clock-canary");
      },
    });
    const snapshot = await clockFailure.loadForPrincipal(PRINCIPAL);
    await expectCode(clockFailure.access(snapshot!), "internal");
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
