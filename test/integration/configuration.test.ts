import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import type { Env } from "../../src/env";
import { runtimeConfiguration } from "../../src/runtime/configuration";

const bound = env as unknown as Env;

function configuration(overrides: Partial<Env>): Env {
  return {
    DB: bound.DB,
    API_RATE_LIMITER: bound.API_RATE_LIMITER,
    ALLOWED_ORIGINS: "",
    ENVIRONMENT: "local",
    PUBLIC_ORIGIN: "http://127.0.0.1:8787",
    GOOGLE_CLIENT_ID: "local-fake-google-client",
    GOOGLE_CLIENT_SECRET: "test-only-fake-google-secret",
    GOOGLE_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9797/authorize",
    GOOGLE_TOKEN_ENDPOINT: "http://127.0.0.1:9797/token",
    GOOGLE_JWKS_URI: "http://127.0.0.1:9797/jwks",
    GOOGLE_ISSUER: "https://accounts.google.com",
    GOOGLE_REVOCATION_ENDPOINT: "http://127.0.0.1:9797/revoke",
    GOOGLE_CALENDAR_API_ORIGIN: "http://127.0.0.1:9797",
    OAUTH_TRANSACTION_KEK_V1: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    TOKEN_KEK_V1: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
    SESSION_PEPPER: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
    IDENTITY_FENCE_KEY: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
    CURSOR_KEY: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
    EVENT_ID_KEY_V1: "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
    ...overrides,
  };
}

describe("fail-closed runtime configuration", () => {
  it("accepts only the exact local origins, paths, issuer, and distinct canonical secrets", async () => {
    await expect(runtimeConfiguration(configuration({}))).resolves.toMatchObject({
      environment: "local",
    });

    for (const hostile of [
      { PUBLIC_ORIGIN: "http://127.0.0.1:8787/path" },
      { PUBLIC_ORIGIN: "http://user@127.0.0.1:8787" },
      { PUBLIC_ORIGIN: "http://localhost:8787" },
      { GOOGLE_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9797/authorize/" },
      { GOOGLE_TOKEN_ENDPOINT: "http://127.0.0.1:9797/token?next=https://attacker.test" },
      { GOOGLE_JWKS_URI: "http://127.0.0.1:9797/jwks#fragment" },
      { GOOGLE_REVOCATION_ENDPOINT: "http://127.0.0.1:9797/token" },
      { GOOGLE_CALENDAR_API_ORIGIN: "http://127.0.0.1:9797/calendar/v3" },
      { GOOGLE_ISSUER: "accounts.google.com" },
      { OAUTH_TRANSACTION_KEK_V1: configuration({}).TOKEN_KEK_V1 },
      { SESSION_PEPPER: "not-a-key" },
    ] satisfies Partial<Env>[]) {
      await expect(runtimeConfiguration(configuration(hostile))).rejects.toThrow();
    }
  });

  it("pins non-local Google endpoints and requires an HTTPS public origin", async () => {
    const production = configuration({
      ENVIRONMENT: "production",
      PUBLIC_ORIGIN: "https://calendar.tasknotes.example",
      GOOGLE_AUTHORIZATION_ENDPOINT: "https://accounts.google.com/o/oauth2/v2/auth",
      GOOGLE_TOKEN_ENDPOINT: "https://oauth2.googleapis.com/token",
      GOOGLE_JWKS_URI: "https://www.googleapis.com/oauth2/v3/certs",
      GOOGLE_REVOCATION_ENDPOINT: "https://oauth2.googleapis.com/revoke",
      GOOGLE_CALENDAR_API_ORIGIN: "https://www.googleapis.com",
    });
    await expect(runtimeConfiguration(production)).resolves.toMatchObject({
      environment: "production",
    });
    await expect(
      runtimeConfiguration({ ...production, GOOGLE_TOKEN_ENDPOINT: "http://127.0.0.1:9797/token" }),
    ).rejects.toThrow();
    await expect(
      runtimeConfiguration({ ...production, PUBLIC_ORIGIN: "http://calendar.tasknotes.example" }),
    ).rejects.toThrow();
  });
});
