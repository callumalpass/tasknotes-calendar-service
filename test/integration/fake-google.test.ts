import { env } from "cloudflare:workers";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";

import {
  exchangeGoogleCalendarCode,
  exchangeGoogleSignInCode,
  googleOidcTestEndpoints,
} from "../../src/auth/google-oidc";
import type { GoogleOidcError } from "../../src/auth/google-oidc";
import {
  googleTestConfiguration,
  listGoogleCalendarsPage,
  listGoogleEventsPage,
  refreshGoogleToken,
  revokeGoogleTokenBestEffort,
} from "../../src/provider/google";
import {
  FAKE_CALENDAR_SCOPE,
  FAKE_GOOGLE_CLIENT_ID,
  FAKE_GOOGLE_CLIENT_SECRET,
  FAKE_GOOGLE_KID,
  FAKE_GOOGLE_ORIGIN,
  FAKE_GOOGLE_REDIRECT_URI,
} from "../support/fake-google";
import type {
  FakeCalendarMode,
  FakeGoogleConfiguration,
  FakeGoogleStats,
  FakeRefreshMode,
  FakeTokenMode,
} from "../support/fake-google";

const fake = (env as unknown as { FAKE_GOOGLE: Fetcher }).FAKE_GOOGLE;
const verifier = "test-only-pkce-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
const endpoints = googleOidcTestEndpoints({
  authorizationEndpoint: `${FAKE_GOOGLE_ORIGIN}/authorize`,
  tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
});
const client = {
  clientId: FAKE_GOOGLE_CLIENT_ID,
  clientSecret: FAKE_GOOGLE_CLIENT_SECRET,
  redirectUri: FAKE_GOOGLE_REDIRECT_URI,
};

// workerd does not implement RequestRedirect "error". Preserve its fail-closed intent by
// converting it to manual and rejecting redirects before returning to production adapters.
const outboundFetch: typeof fetch = async (input, init) => {
  const adjusted =
    init === undefined
      ? undefined
      : {
          ...init,
          ...(init.redirect === undefined
            ? {}
            : { redirect: init.redirect === "error" ? ("manual" as const) : init.redirect }),
        };
  const response = await fetch(input, adjusted);
  if (init?.redirect === "error" && response.status >= 300 && response.status < 400) {
    throw new TypeError("outbound redirect rejected");
  }
  return response;
};

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function sha256(value: string): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
  );
}

async function control(path: string, init?: RequestInit): Promise<Response> {
  return fake.fetch(`https://fake-google-control.test${path}`, init);
}

async function configure(value: FakeGoogleConfiguration): Promise<void> {
  const response = await control("/configure", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  expect(response.status).toBe(204);
}

async function statistics(): Promise<FakeGoogleStats> {
  const response = await control("/stats");
  return response.json<FakeGoogleStats>();
}

interface Grant {
  code: string;
  nonce: string;
  scopes: string;
  state: string;
}

async function authorize(calendar = false): Promise<Grant> {
  const state = "state-for-isolated-fake-google-test";
  const nonce = "nonce-for-isolated-fake-google-test";
  const scopes = ["openid", "email", "profile", ...(calendar ? [FAKE_CALENDAR_SCOPE] : [])].join(
    " ",
  );
  const url = new URL(`${FAKE_GOOGLE_ORIGIN}/authorize`);
  url.search = new URLSearchParams({
    client_id: FAKE_GOOGLE_CLIENT_ID,
    redirect_uri: FAKE_GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: scopes,
    state,
    nonce,
    code_challenge: await sha256(verifier),
    code_challenge_method: "S256",
    ...(calendar ? { access_type: "offline", prompt: "consent" } : {}),
  }).toString();
  const response = await fake.fetch(new Request(url, { redirect: "manual" }));
  expect(response.status).toBe(302);
  const callback = new URL(response.headers.get("location") ?? "missing:");
  expect(callback.origin + callback.pathname).toBe(FAKE_GOOGLE_REDIRECT_URI);
  return {
    code: callback.searchParams.get("code") ?? "",
    nonce,
    scopes,
    state,
  };
}

function tokenBody(code: string, codeVerifier = verifier): URLSearchParams {
  return new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: FAKE_GOOGLE_CLIENT_ID,
    client_secret: FAKE_GOOGLE_CLIENT_SECRET,
    redirect_uri: FAKE_GOOGLE_REDIRECT_URI,
    code_verifier: codeVerifier,
  });
}

function exchange(code: string, codeVerifier = verifier): Promise<Response> {
  return fetch(`${FAKE_GOOGLE_ORIGIN}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody(code, codeVerifier),
    redirect: "manual",
  });
}

async function jwks(): Promise<{ keys: JsonWebKey[] }> {
  const response = await fetch(`${FAKE_GOOGLE_ORIGIN}/jwks`, { redirect: "manual" });
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("public, max-age=300");
  const value = await response.json<{ keys: JsonWebKey[] }>();
  expect(value.keys).toHaveLength(1);
  expect(value.keys[0]).toMatchObject({ kid: FAKE_GOOGLE_KID, kty: "RSA", alg: "RS256" });
  expect(value.keys[0]).not.toHaveProperty("d");
  return value;
}

beforeEach(async () => {
  const response = await control("/reset", { method: "POST" });
  expect(response.status).toBe(204);
});

describe("isolated workerd fake Google", () => {
  it("runs authorize -> token -> public JWKS verification through actual services", async () => {
    const grant = await authorize(true);
    const response = await exchange(grant.code);
    expect(response.status).toBe(200);
    const tokens = await response.json<Record<string, unknown>>();
    expect(tokens).toMatchObject({
      token_type: "Bearer",
      expires_in: 3600,
      scope: grant.scopes,
    });
    expect(tokens["refresh_token"]).toBeTypeOf("string");

    const keys = await jwks();
    const verified = await jwtVerify(String(tokens["id_token"]), createLocalJWKSet(keys), {
      algorithms: ["RS256"],
      issuer: "https://accounts.google.com",
      audience: FAKE_GOOGLE_CLIENT_ID,
    });
    expect(verified.payload).toMatchObject({
      sub: "fake-google-subject-001",
      email: "fake.user@example.test",
      email_verified: true,
      nonce: grant.nonce,
      azp: FAKE_GOOGLE_CLIENT_ID,
    });
  });

  it("integrates with the production OIDC verifier for sign-in and Calendar consent", async () => {
    const keyResolver = createLocalJWKSet(await jwks());
    const signIn = await authorize();
    await expect(
      exchangeGoogleSignInCode(
        endpoints,
        client,
        {
          code: signIn.code,
          codeVerifier: verifier,
          expectedNonceHash: await sha256(signIn.nonce),
        },
        { fetch: outboundFetch, keyResolver },
      ),
    ).resolves.toMatchObject({
      subject: "fake-google-subject-001",
      email: "fake.user@example.test",
    });

    const calendar = await authorize(true);
    await expect(
      exchangeGoogleCalendarCode(
        endpoints,
        client,
        {
          code: calendar.code,
          codeVerifier: verifier,
          expectedNonceHash: await sha256(calendar.nonce),
          expectedSubject: "fake-google-subject-001",
          requiredCalendarScopes: [FAKE_CALENDAR_SCOPE],
        },
        { fetch: outboundFetch, keyResolver },
      ),
    ).resolves.toMatchObject({
      identity: { subject: "fake-google-subject-001" },
      tokenMaterial: { scopes: ["openid", "email", "profile", FAKE_CALENDAR_SCOPE] },
    });
  });

  it("atomically consumes one code before response formation under concurrency", async () => {
    const grant = await authorize();
    const responses = await Promise.all(Array.from({ length: 20 }, () => exchange(grant.code)));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 400)).toHaveLength(19);
    await Promise.all(
      responses
        .filter((response) => response.status === 400)
        .map(async (response) => expect(await response.json()).toEqual({ error: "invalid_grant" })),
    );
    expect(await statistics()).toMatchObject({ tokenRequests: 20, uniqueCodeExchanges: 1 });
  });

  it("consumes a code on PKCE mismatch and on configured provider failure", async () => {
    const badPkce = await authorize();
    expect((await exchange(badPkce.code, "x".repeat(43))).status).toBe(400);
    expect((await exchange(badPkce.code)).status).toBe(400);

    const failed = await authorize();
    await configure({ token: "consume_then_fail" });
    expect((await exchange(failed.code)).status).toBe(500);
    expect((await exchange(failed.code)).status).toBe(400);
    expect(await statistics()).toMatchObject({ tokenRequests: 4, uniqueCodeExchanges: 2 });
  });

  it("fails closed for hostile forms, methods, paths, hosts, and redirect following", async () => {
    const grant = await authorize();
    const duplicate = tokenBody(grant.code);
    duplicate.append("code", grant.code);
    expect(
      (
        await fetch(`${FAKE_GOOGLE_ORIGIN}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: duplicate,
        })
      ).status,
    ).toBe(400);
    expect((await exchange(grant.code)).status).toBe(200); // malformed requests do not consume

    for (const request of [
      new Request(`${FAKE_GOOGLE_ORIGIN}/authorize?unknown=1`),
      new Request(`${FAKE_GOOGLE_ORIGIN}/jwks`, { method: "POST" }),
      new Request(`${FAKE_GOOGLE_ORIGIN}/calendar/v3/private/write`, { method: "POST" }),
      new Request("https://oauth2.googleapis.com/token", { method: "POST" }),
      new Request("https://attacker.example/collect"),
    ]) {
      expect((await fetch(request, { redirect: "manual" })).status).toBeGreaterThanOrEqual(400);
    }

    const redirected = await authorize();
    const authUrl = new URL(`${FAKE_GOOGLE_ORIGIN}/authorize`);
    authUrl.search = new URLSearchParams({
      client_id: FAKE_GOOGLE_CLIENT_ID,
      redirect_uri: FAKE_GOOGLE_REDIRECT_URI,
      response_type: "code",
      scope: redirected.scopes,
      state: redirected.state,
      nonce: redirected.nonce,
      code_challenge: await sha256(verifier),
      code_challenge_method: "S256",
    }).toString();
    await expect(outboundFetch(authUrl, { redirect: "error" })).rejects.toThrow(
      "outbound redirect rejected",
    );
  });

  it("returns bounded denial metadata for known and unknown OAuth errors", async () => {
    for (const [mode, expected] of [
      ["access_denied", "access_denied"],
      ["unknown_error", "fake_unknown_oauth_error"],
    ] as const) {
      await configure({ authorization: mode });
      const state = `denial-${mode}`;
      const nonce = "denial-nonce";
      const url = new URL(`${FAKE_GOOGLE_ORIGIN}/authorize`);
      url.search = new URLSearchParams({
        client_id: FAKE_GOOGLE_CLIENT_ID,
        redirect_uri: FAKE_GOOGLE_REDIRECT_URI,
        response_type: "code",
        scope: "openid email profile",
        state,
        nonce,
        code_challenge: await sha256(verifier),
        code_challenge_method: "S256",
      }).toString();
      const response = await fake.fetch(new Request(url, { redirect: "manual" }));
      const callback = new URL(response.headers.get("location") ?? "missing:");
      expect(callback.searchParams.get("error")).toBe(expected);
      expect(callback.searchParams.get("state")).toBe(state);
      expect(callback.searchParams.get("error_description")?.length).toBeLessThan(256);
      expect(callback.searchParams.has("code")).toBe(false);
    }
  });

  it("emits configured identity, claim, scope, refresh, and HTTP failure modes", async () => {
    await configure({ subject: "different-fake-subject", email: "same@example.test" });
    const identity = await authorize();
    const identityPayload = await (await exchange(identity.code)).json<Record<string, unknown>>();
    expect(decodeJwt(String(identityPayload["id_token"]))).toMatchObject({
      sub: "different-fake-subject",
      email: "same@example.test",
    });

    const modes: FakeTokenMode[] = [
      "wrong_nonce",
      "wrong_issuer",
      "alternate_issuer",
      "wrong_audience",
      "wrong_azp",
      "wrong_signature",
      "expired",
      "omitted_scope",
      "writable_scope",
      "missing_refresh_token",
      "rate_limited",
    ];
    for (const mode of modes) {
      const grant = await authorize(true);
      await configure({ token: mode });
      const response = await exchange(grant.code);
      if (mode === "rate_limited") {
        expect(response.status).toBe(429);
        continue;
      }
      const value = await response.json<Record<string, unknown>>();
      if (mode === "omitted_scope") expect(value).not.toHaveProperty("scope");
      else if (mode === "writable_scope") expect(value["scope"]).toContain("/auth/calendar");
      else if (mode === "missing_refresh_token") expect(value).not.toHaveProperty("refresh_token");
      else {
        const payload = decodeJwt(String(value["id_token"]));
        if (mode === "wrong_nonce") expect(payload["nonce"]).not.toBe(grant.nonce);
        if (mode === "wrong_issuer") expect(payload.iss).toBe("https://attacker.invalid");
        if (mode === "alternate_issuer") expect(payload.iss).toBe("accounts.google.com");
        if (mode === "wrong_audience") expect(payload.aud).not.toBe(FAKE_GOOGLE_CLIENT_ID);
        if (mode === "wrong_azp") expect(payload["azp"]).not.toBe(FAKE_GOOGLE_CLIENT_ID);
        if (mode === "expired") expect(payload.exp).toBeLessThan(Math.floor(Date.now() / 1_000));
        if (mode === "wrong_signature") {
          await expect(
            jwtVerify(String(value["id_token"]), createLocalJWKSet(await jwks())),
          ).rejects.toThrow();
        }
      }
    }
  });

  it("supports timeout fault injection without allowing replay", async () => {
    const grant = await authorize();
    await configure({ token: "stall" });
    await expect(
      exchangeGoogleSignInCode(
        endpoints,
        client,
        { code: grant.code, codeVerifier: verifier, expectedNonceHash: await sha256(grant.nonce) },
        {
          fetch: outboundFetch,
          keyResolver: createLocalJWKSet(await jwks()),
          timeoutMilliseconds: 25,
        },
      ),
    ).rejects.toMatchObject({
      code: "provider_exchange_failed",
    } satisfies Partial<GoogleOidcError>);
    expect((await exchange(grant.code)).status).toBe(400);
  });

  it("records revocation and allowlisted Calendar reads, including faults", async () => {
    await configure({ calendarEnabled: true });
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    await expect(
      revokeGoogleTokenBestEffort({
        configuration: provider,
        token: "fake-revoke-secret",
        fetch: outboundFetch,
      }),
    ).resolves.toEqual({ ok: true, value: undefined });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: true, value: { items: [{ id: "fake-calendar" }] } });
    await expect(
      listGoogleEventsPage({
        configuration: provider,
        accessToken: "fake-access",
        calendarId: "fake-calendar",
        timeMin: "2026-03-01T00:00:00Z",
        timeMax: "2026-04-01T00:00:00Z",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: true, value: { items: [] } });

    await configure({ calendar: "rate_limited" });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "rate_limited", retryAfterSeconds: 3 } });
    await configure({ calendar: "malformed_shape" });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "invalid_response" } });
    expect(await statistics()).toMatchObject({ revokeCalls: 1, calendarCalls: 4 });
  });

  it("strictly refreshes, rotates, omits optional fields, and atomically rejects rotated-token concurrency", async () => {
    const grant = await authorize(true);
    const issued = await (await exchange(grant.code)).json<Record<string, unknown>>();
    const refreshToken = String(issued["refresh_token"]);
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    const refresh = (token: string, timeoutMs = 1_000) =>
      refreshGoogleToken({
        configuration: provider,
        clientId: FAKE_GOOGLE_CLIENT_ID,
        clientSecret: FAKE_GOOGLE_CLIENT_SECRET,
        refreshToken: token,
        fetch: outboundFetch,
        timeoutMs,
      });

    await expect(refresh(refreshToken)).resolves.toMatchObject({
      ok: true,
      value: { expiresInSeconds: 3_600, scope: grant.scopes, refreshToken },
    });
    await configure({ refresh: "omit_refresh" });
    const omittedRefresh = await refresh(refreshToken);
    expect(omittedRefresh).toMatchObject({ ok: true, value: { scope: grant.scopes } });
    if (omittedRefresh.ok) expect(omittedRefresh.value).not.toHaveProperty("refreshToken");
    await configure({ refresh: "omit_scope" });
    const omittedScope = await refresh(refreshToken);
    expect(omittedScope).toMatchObject({ ok: true, value: { refreshToken } });
    if (omittedScope.ok) expect(omittedScope.value).not.toHaveProperty("scope");

    await configure({ refresh: "rotate" });
    const rotated = await refresh(refreshToken);
    expect(rotated.ok).toBe(true);
    if (!rotated.ok || rotated.value.refreshToken === undefined) throw new Error("rotation failed");
    expect(rotated.value.refreshToken).not.toBe(refreshToken);
    await expect(refresh(refreshToken)).resolves.toMatchObject({
      ok: false,
      error: { code: "reauthorization_required" },
    });

    await configure({ refresh: "rotate" });
    const concurrent = await Promise.all(
      Array.from({ length: 12 }, () => refresh(rotated.value.refreshToken ?? "missing")),
    );
    expect(concurrent.filter((result) => result.ok)).toHaveLength(1);
    expect(concurrent.filter((result) => !result.ok)).toHaveLength(11);
    expect(await statistics()).toMatchObject({ refreshRequests: 17, successfulRefreshes: 5 });
  });

  it("enforces the exact refresh form and models refresh scope and failure responses", async () => {
    const grant = await authorize(true);
    const issued = await (await exchange(grant.code)).json<Record<string, unknown>>();
    const refreshToken = String(issued["refresh_token"]);
    const body = () =>
      new URLSearchParams({
        client_id: FAKE_GOOGLE_CLIENT_ID,
        client_secret: FAKE_GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
      });
    const direct = (form: URLSearchParams) =>
      fetch(`${FAKE_GOOGLE_ORIGIN}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form,
        redirect: "manual",
      });
    const extra = body();
    extra.set("scope", FAKE_CALENDAR_SCOPE);
    expect((await direct(extra)).status).toBe(400);
    const duplicate = body();
    duplicate.append("refresh_token", refreshToken);
    expect((await direct(duplicate)).status).toBe(400);
    const wrongSecret = body();
    wrongSecret.set("client_secret", "wrong-fake-secret");
    expect((await direct(wrongSecret)).status).toBe(400);

    for (const [mode, status] of [
      ["invalid_grant", 400],
      ["rate_limited", 429],
      ["server_error", 500],
    ] as const satisfies readonly (readonly [FakeRefreshMode, number])[]) {
      await configure({ refresh: mode });
      expect((await direct(body())).status).toBe(status);
    }
    for (const mode of ["writable_scope", "unknown_scope"] as const) {
      await configure({ refresh: mode });
      const value = await (await direct(body())).json<Record<string, unknown>>();
      expect(value["scope"]).toContain(
        mode === "writable_scope" ? "/auth/calendar" : "fake.unknown.scope",
      );
    }
    for (const mode of [
      "malformed_json",
      "malformed_shape",
      "oversized_declared",
      "oversized_streamed",
    ] as const) {
      await configure({ refresh: mode });
      const provider = googleTestConfiguration({
        tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
        revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
        calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
      });
      await expect(
        refreshGoogleToken({
          configuration: provider,
          clientId: FAKE_GOOGLE_CLIENT_ID,
          clientSecret: FAKE_GOOGLE_CLIENT_SECRET,
          refreshToken,
          fetch: outboundFetch,
        }),
      ).resolves.toMatchObject({ ok: false, error: { code: "invalid_response" } });
    }
    await configure({ refresh: "stall" });
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    await expect(
      refreshGoogleToken({
        configuration: provider,
        clientId: FAKE_GOOGLE_CLIENT_ID,
        clientSecret: FAKE_GOOGLE_CLIENT_SECRET,
        refreshToken,
        fetch: outboundFetch,
        timeoutMs: 25,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "timeout" } });
  });

  it("validates exact Calendar projections and paginates mutable complete calendar fixtures", async () => {
    await configure({
      calendarEnabled: true,
      calendarPages: [
        {
          items: [
            {
              id: "provider-calendar-one",
              summary: "Primary",
              description: "Complete fixture",
              timeZone: "Europe/London",
              accessRole: "owner",
              primary: true,
              selected: true,
            },
          ],
          nextPageToken: "p".repeat(1_024),
        },
        {
          items: [
            {
              id: "provider-calendar-two",
              summary: "Shared",
              accessRole: "reader",
              selected: false,
            },
          ],
        },
      ],
    });
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    const first = await listGoogleCalendarsPage({
      configuration: provider,
      accessToken: "fake-access",
      fetch: outboundFetch,
    });
    expect(first).toMatchObject({
      ok: true,
      value: {
        items: [{ id: "provider-calendar-one", timeZone: "Europe/London", access: "owner" }],
      },
    });
    if (!first.ok || first.value.nextPageToken === undefined) throw new Error("missing next page");
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        pageToken: first.value.nextPageToken,
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: true, value: { items: [{ id: "provider-calendar-two" }] } });

    const exact = new URL(`${FAKE_GOOGLE_ORIGIN}/calendar/v3/users/me/calendarList`);
    exact.searchParams.set("maxResults", "251");
    exact.searchParams.set("fields", "*");
    const rejected = await fake.fetch(exact, {
      headers: { authorization: "Bearer fake-access", accept: "application/json" },
    });
    expect(rejected.status).toBe(400);
    expect(await rejected.text()).not.toContain("provider-calendar-one");
    expect((await fake.fetch(exact, { method: "POST" })).status).toBe(405);

    await configure({
      calendarPages: [
        { items: [{ id: "replacement-calendar", summary: "Replacement", accessRole: "writer" }] },
      ],
    });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({
      ok: true,
      value: { items: [{ id: "replacement-calendar", access: "writer" }] },
    });
    await configure({ calendarPages: [{ items: [], nextPageToken: "x".repeat(1_025) }] });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "invalid_response" } });
    await configure({ calendarPages: [{ items: [], nextPageToken: "bad\ncontrol" }] });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "invalid_response" } });
  });

  it("serves exact event pages with timed, all-day, recurrence, cancellation, and mutations", async () => {
    await configure({
      calendarEnabled: true,
      eventPages: [
        {
          calendarId: "calendar/id @ test",
          nextPageToken: "events-next",
          items: [
            {
              id: "timed-provider-id",
              status: "confirmed",
              updated: "2026-03-01T10:00:00Z",
              summary: "Timed",
              start: { dateTime: "2026-03-02T10:00:00Z" },
              end: { dateTime: "2026-03-02T11:00:00Z" },
            },
            {
              id: "all-day-provider-id",
              status: "confirmed",
              updated: "2026-03-01T10:00:00Z",
              start: { date: "2026-03-03" },
              end: { date: "2026-03-05" },
            },
            {
              id: "instance-provider-id",
              status: "tentative",
              updated: "2026-03-01T10:00:00Z",
              start: { dateTime: "2026-03-06T10:00:00Z" },
              end: { dateTime: "2026-03-06T11:00:00Z" },
              recurringEventId: "series-provider-id",
              originalStartTime: { dateTime: "2026-03-06T10:00:00Z" },
            },
          ],
        },
        {
          calendarId: "calendar/id @ test",
          items: [
            { id: "deleted-provider-id", status: "cancelled", updated: "2026-03-07T10:00:00Z" },
          ],
        },
      ],
    });
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    const request = {
      configuration: provider,
      accessToken: "fake-access",
      calendarId: "calendar/id @ test",
      timeMin: "2026-03-01T00:00:00Z",
      timeMax: "2026-04-01T00:00:00Z",
      fetch: outboundFetch,
    } as const;
    const first = await listGoogleEventsPage(request);
    expect(first).toMatchObject({
      ok: true,
      value: {
        items: [
          { id: "timed-provider-id" },
          { id: "all-day-provider-id", end: { kind: "all_day", date: "2026-03-05" } },
          { recurrence: { seriesId: "series-provider-id" } },
        ],
      },
    });
    if (!first.ok || first.value.nextPageToken === undefined)
      throw new Error("missing events page");
    await expect(
      listGoogleEventsPage({ ...request, pageToken: first.value.nextPageToken }),
    ).resolves.toMatchObject({
      ok: true,
      value: { items: [{ id: "deleted-provider-id", status: "cancelled" }] },
    });
    await configure({
      eventPages: [
        {
          calendarId: "calendar/id @ test",
          items: [
            {
              id: "changed-provider-id",
              status: "confirmed",
              updated: "2026-03-08T10:00:00Z",
              start: { dateTime: "2026-03-09T10:00:00Z" },
              end: { dateTime: "2026-03-09T11:00:00Z" },
            },
          ],
        },
      ],
    });
    await expect(listGoogleEventsPage(request)).resolves.toMatchObject({
      ok: true,
      value: { items: [{ id: "changed-provider-id" }] },
    });
  });

  it("classifies Calendar HTTP, malformed, size, and stalled-body faults", async () => {
    await configure({ calendarEnabled: true });
    const provider = googleTestConfiguration({
      tokenEndpoint: `${FAKE_GOOGLE_ORIGIN}/token`,
      revocationEndpoint: `${FAKE_GOOGLE_ORIGIN}/revoke`,
      calendarApiOrigin: FAKE_GOOGLE_ORIGIN,
    });
    const expected: readonly (readonly [FakeCalendarMode, string])[] = [
      ["unauthorized", "unauthorized"],
      ["permission_denied", "permission_denied"],
      ["quota_exceeded", "rate_limited"],
      ["rate_limited", "rate_limited"],
      ["not_found", "not_found"],
      ["server_error", "unavailable"],
      ["malformed_json", "invalid_response"],
      ["malformed_shape", "invalid_response"],
      ["oversized_declared", "invalid_response"],
      ["oversized_streamed", "invalid_response"],
    ];
    for (const [mode, code] of expected) {
      await configure({ calendar: mode });
      await expect(
        listGoogleCalendarsPage({
          configuration: provider,
          accessToken: "fake-access",
          fetch: outboundFetch,
        }),
      ).resolves.toMatchObject({ ok: false, error: { code } });
    }
    await configure({ calendar: "stall" });
    await expect(
      listGoogleCalendarsPage({
        configuration: provider,
        accessToken: "fake-access",
        fetch: outboundFetch,
        timeoutMs: 25,
      }),
    ).resolves.toMatchObject({ ok: false, error: { code: "timeout" } });
  });

  it("never exposes keys, codes, tokens, identity values, or hostile input in control output", async () => {
    const grant = await authorize(true);
    await exchange(grant.code);
    await fetch("https://attacker.example/private-value-from-hostile-request");
    const statsResponse = await control("/stats");
    const statsText = await statsResponse.text();
    for (const secret of [
      grant.code,
      verifier,
      FAKE_GOOGLE_CLIENT_SECRET,
      "fake-access-token",
      "fake-refresh-token",
      "fake.user@example.test",
      "private-value-from-hostile-request",
      '"d"',
    ]) {
      expect(statsText).not.toContain(secret);
    }
    expect(Object.keys(JSON.parse(statsText) as object).sort()).toEqual([
      "authorizationRequests",
      "calendarCalls",
      "calendarListCalls",
      "eventCalls",
      "refreshRequests",
      "rejectedRequests",
      "revokeCalls",
      "successfulRefreshes",
      "tokenRequests",
      "uniqueCodeExchanges",
    ]);
    const error = await control("/configure", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ unknown: "private-value-from-hostile-request" }),
    });
    expect(await error.text()).not.toContain("private-value-from-hostile-request");
  });
});
