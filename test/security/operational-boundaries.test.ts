import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { routes } from "../../src/contracts";
import { createPkceS256Challenge } from "../../src/crypto/pkce";
import type { Env } from "../../src/env";
import { createWorker } from "../../src/index";
import { allowedOriginsFromEnvironment } from "../../src/runtime/configuration";
import type { FakeGoogleConfiguration } from "../support/fake-google";

const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher; TEST_RATE_LIMITER: RateLimit };
const worker = createWorker();
const verifier = "canary-client-verifier-abcdefghijklmnopqrstuvwxyz0123456789";

async function send(
  path: string,
  init: RequestInit = {},
  configured: Env = bindings,
): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(
    new Request(`http://127.0.0.1:8787${path}`, init),
    configured,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

function post(
  path: string,
  body: unknown,
  credential?: string,
  configured: Env = bindings,
): Promise<Response> {
  return send(
    path,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(credential === undefined ? {} : { authorization: `Bearer ${credential}` }),
      },
      body: JSON.stringify(body),
    },
    configured,
  );
}

async function configure(value: FakeGoogleConfiguration): Promise<void> {
  const response = await bindings.FAKE_GOOGLE.fetch("https://fake-google-control.test/configure", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  expect(response.status).toBe(204);
}

interface Started {
  transaction_id: string;
  polling_secret: string;
  authorization_url: string;
}

async function grant(
  path: string,
  credential?: string,
): Promise<{ response: Response; started: Started; callback: URL }> {
  const start = await post(
    path,
    {
      client_kind: "obsidian",
      device_name: "canary-device",
      code_challenge: await createPkceS256Challenge(verifier),
    },
    credential,
  );
  expect(start.status).toBe(201);
  const started = await start.json<Started>();
  const authorization = await bindings.FAKE_GOOGLE.fetch(
    new Request(started.authorization_url, { redirect: "manual" }),
  );
  const callback = new URL(authorization.headers.get("location") ?? "missing:");
  const completed = await send(`${callback.pathname}${callback.search}`);
  expect(completed.status).toBe(200);
  const code = /class="code"[^>]*>([A-Z2-9]{8})</u.exec(await completed.text())?.[1];
  const response = await post(
    `${path.replace(/\/start$/, "")}/${started.transaction_id}/redeem`,
    {
      polling_secret: started.polling_secret,
      code_verifier: verifier,
      ...(code === undefined ? {} : { confirmation_code: code }),
    },
    credential,
  );
  expect(response.status).toBe(200);
  return { response, started, callback };
}

async function signIn(): Promise<string> {
  const signedIn = await grant("/v1/sign-in/start");
  return (await signedIn.response.json<{ session: { credential: string } }>()).session.credential;
}

beforeEach(async () => {
  expect(
    (await bindings.FAKE_GOOGLE.fetch("https://fake-google-control.test/reset", { method: "POST" }))
      .status,
  ).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

afterEach(() => vi.restoreAllMocks());

describe("router operational boundaries in workerd", () => {
  it("declares the rate-limit authority for every route", () => {
    for (const route of routes) {
      expect(route.rateLimit).toBe(
        route.authenticated ? "principal" : route.name.startsWith("signIn") ? "ip" : "none",
      );
    }
  });

  it("enforces the native rate binding by IP before parsing anonymous bodies", async () => {
    const configured = { ...bindings, IP_RATE_LIMITER: bindings.TEST_RATE_LIMITER };
    const ip = "198.51.100.1";
    const request = { method: "POST", headers: { "cf-connecting-ip": ip } };
    expect((await send("/v1/sign-in/start", request, configured)).status).toBe(415);
    for (const suffix of ["status", "redeem"]) {
      const response = await send(`/v1/sign-in/${"A".repeat(43)}/${suffix}`, request, configured);
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("60");
      await expect(response.json()).resolves.toMatchObject({ code: "rate_limited" });
    }
    expect(
      (
        await send(
          "/v1/sign-in/start",
          { ...request, headers: { "cf-connecting-ip": "198.51.100.2" } },
          configured,
        )
      ).status,
    ).toBe(415);
    expect((await send("/health/live", {}, configured)).status).toBe(200);
    expect((await send("/oauth/google/callback", {}, configured)).status).toBe(400);
  });

  it("uses principal identity across sessions and IPs, not bearer credentials", async () => {
    const first = await signIn();
    const second = await signIn();
    const configured = { ...bindings, PRINCIPAL_RATE_LIMITER: bindings.TEST_RATE_LIMITER };
    const current = await send(
      "/v1/session",
      { headers: { authorization: `Bearer ${first}`, "cf-connecting-ip": "192.0.2.1" } },
      configured,
    );
    expect(current.status).toBe(200);
    const other = await send(
      "/v1/devices",
      { headers: { authorization: `Bearer ${second}`, "cf-connecting-ip": "192.0.2.2" } },
      configured,
    );
    expect(other.status).toBe(429);
    await configure({ subject: "other-principal" });
    const third = await signIn();
    expect(
      (await send("/v1/session", { headers: { authorization: `Bearer ${third}` } }, configured))
        .status,
    ).toBe(200);
    expect((await send("/v1/session", {}, configured)).status).toBe(401);
  });

  it("fails closed when the rate binding fails, while health and callback stay unlimited", async () => {
    const broken = { limit: () => Promise.reject(new Error("canary-binding-secret")) };
    const configured = { ...bindings, IP_RATE_LIMITER: broken };
    const response = await send("/v1/sign-in/start", { method: "POST" }, configured);
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("60");
    expect(
      await bindings.DB.prepare("SELECT COUNT(*) AS count FROM oauth_transactions").first(),
    ).toEqual({ count: 0 });
    expect((await send("/health/live", {}, configured)).status).toBe(200);
    expect((await send("/oauth/google/callback", {}, configured)).status).toBe(400);
  });

  it("keeps the sign-in and signed-in allowances apart", async () => {
    const credential = await signIn();
    const session = { headers: { authorization: `Bearer ${credential}` } };
    const broken = { limit: () => Promise.reject(new Error("canary-binding-secret")) };
    const withoutIp = { ...bindings, IP_RATE_LIMITER: broken };
    expect((await send("/v1/session", session, withoutIp)).status).toBe(200);
    expect((await send("/v1/sign-in/start", { method: "POST" }, withoutIp)).status).toBe(503);
    const withoutPrincipal = { ...bindings, PRINCIPAL_RATE_LIMITER: broken };
    expect((await send("/v1/session", session, withoutPrincipal)).status).toBe(503);
    expect((await send("/v1/sign-in/start", { method: "POST" }, withoutPrincipal)).status).toBe(
      415,
    );
  });

  it.each([
    "https://web.tasknotes.test",
    "app://obsidian.md",
    "capacitor://app.tasknotes.dev",
    "http://localhost",
  ])("allows exact preflight and response origin %s", async (origin) => {
    const configured = { ...bindings, ALLOWED_ORIGINS: origin };
    const preflight = await send(
      "/v1/session",
      {
        method: "OPTIONS",
        headers: {
          origin,
          "access-control-request-method": "GET",
          "access-control-request-headers": "Authorization, Content-Type, If-Match",
        },
      },
      configured,
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe(origin);
    expect(preflight.headers.get("access-control-allow-methods")).toBe("GET");
    expect(preflight.headers.get("access-control-allow-credentials")).toBe("true");
    expect(preflight.headers.get("vary")).toBe("Origin");
    const response = await send("/v1/session", { headers: { origin } }, configured);
    expect(response.status).toBe(401);
    expect(response.headers.get("access-control-allow-origin")).toBe(origin);
    expect(response.headers.get("access-control-expose-headers")).toBe("x-request-id, Retry-After");
    expect(response.headers.get("x-request-id")).toMatch(/^[a-f0-9-]{36}$/);
  });

  it("rejects unknown routes, methods, headers and lookalike origins in preflights", async () => {
    const configured = { ...bindings, ALLOWED_ORIGINS: "https://web.tasknotes.test" };
    for (const [path, method, origin, header, status] of [
      ["/not-a-route", "GET", "https://web.tasknotes.test", "Authorization", 404],
      ["/v1/session", "POST", "https://web.tasknotes.test", "Authorization", 404],
      ["/v1/session", "GET", "https://web.tasknotes.test.attacker.test", "Authorization", 403],
      ["/v1/session", "GET", "https://web.tasknotes.test", "X-Secret", 403],
      ["/v1/session", "GET", "null", "Authorization", 403],
    ] as const) {
      expect(
        (
          await send(
            path,
            {
              method: "OPTIONS",
              headers: {
                origin,
                "access-control-request-method": method,
                "access-control-request-headers": header,
              },
            },
            configured,
          )
        ).status,
      ).toBe(status);
    }
    for (const origin of ["https://web.tasknotes.test.attacker.test", "null"]) {
      expect(
        (await send("/health/live", { headers: { origin } }, configured)).headers.get(
          "access-control-allow-origin",
        ),
      ).toBeNull();
    }
    expect(
      (await send("/health/live", { headers: { origin: "app://obsidian.md" } })).headers.get(
        "access-control-allow-origin",
      ),
    ).toBeNull();
  });

  it("validates the configured origin list rather than accepting paths, credentials, null or wildcards", () => {
    expect(allowedOriginsFromEnvironment(bindings)).toEqual([]);
    expect(
      allowedOriginsFromEnvironment({
        ...bindings,
        ALLOWED_ORIGINS: "https://one.test, https://two.test",
      }),
    ).toEqual(["https://one.test", "https://two.test"]);
    for (const origin of [
      "*",
      "null",
      "https://one.test/path",
      "https://one.test/",
      "https://user@one.test",
      "https://one.test?x=1",
      "https://one.test#secret",
      "https://one.test,",
      "app://attacker.test",
      "capacitor://localhost",
    ]) {
      expect(() =>
        allowedOriginsFromEnvironment({ ...bindings, ALLOWED_ORIGINS: origin }),
      ).toThrow();
    }
  });

  it("does not initialize misconfigured runtime on liveness, and safely reports initialization errors", async () => {
    const output = vi.spyOn(console, "log");
    const errors = vi.spyOn(console, "error");
    const configured = { ...bindings, SESSION_PEPPER: "canary-invalid-secret" };
    expect((await send("/health/live", {}, configured)).status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(errors).not.toHaveBeenCalled();
    expect(
      (
        await send(
          "/v1/sign-in/start",
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              client_kind: "obsidian",
              device_name: "Browser",
              code_challenge: await createPkceS256Challenge(verifier),
            }),
          },
          configured,
        )
      ).status,
    ).toBe(500);
    expect(errors.mock.calls).toEqual([
      [{ error_class: "SecretConfigurationError", location: "http.router" }],
    ]);
    expect(JSON.stringify(output.mock.calls)).not.toContain("canary-invalid-secret");
  });

  it("captures real request telemetry across sign-in, event reads and failed provider calls without secrets", async () => {
    const output = vi.spyOn(console, "log");
    const errors = vi.spyOn(console, "error");
    const providerId = "canary-private-provider-calendar";
    const title = "canary-private-event-title";
    await configure({
      calendarEnabled: true,
      subject: "canary-google-subject",
      email: "canary@example.test",
      calendarPages: [
        { items: [{ id: providerId, summary: "canary-calendar-title", accessRole: "owner" }] },
      ],
      eventPages: [
        {
          calendarId: providerId,
          items: [
            {
              id: "canary-provider-event-id",
              etag: '"1"',
              summary: title,
              status: "confirmed",
              updated: "2026-01-01T00:00:00Z",
              start: { date: "2026-01-01" },
              end: { date: "2026-01-02" },
            },
          ],
        },
      ],
    });
    const signedIn = await grant("/v1/sign-in/start");
    const credential = (await signedIn.response.json<{ session: { credential: string } }>()).session
      .credential;
    await grant("/v1/connections/google/start", credential);
    const headers = { authorization: `Bearer ${credential}` };
    const discovery = await send("/v1/calendars", { headers });
    expect(discovery.status).toBe(200);
    const calendarId = (await discovery.json<{ calendars: { id: string }[] }>()).calendars[0]?.id;
    if (calendarId === undefined) throw new Error("missing discovered calendar");
    const path = `/v1/calendars/${calendarId}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`;
    const events = await send(path, { headers });
    expect(events.status).toBe(200);
    expect(await events.text()).toContain(title);
    await configure({ calendar: "server_error" });
    const failed = await send(path, { headers });
    expect(failed.status).toBe(503);
    const captured = JSON.stringify([output.mock.calls, errors.mock.calls]);
    for (const canary of [
      providerId,
      title,
      "canary-private-provider-calendar",
      "canary-provider-event-id",
      "canary-google-subject",
      "canary@example.test",
      "canary-calendar-title",
      "canary-device",
      credential,
      verifier,
      bindings.GOOGLE_CLIENT_SECRET,
      bindings.TOKEN_KEK_V1,
      bindings.SESSION_PEPPER,
      bindings.OAUTH_TRANSACTION_KEK_V1,
      bindings.IDENTITY_FENCE_KEY,
      bindings.CURSOR_KEY,
      bindings.EVENT_ID_KEY_V1,
      "fake-access-token-000000000000000000000001",
      "fake-refresh-token-000000000000000000001",
      signedIn.started.polling_secret,
      signedIn.started.transaction_id,
      calendarId,
      signedIn.callback.searchParams.get("code"),
      new URL(signedIn.started.authorization_url).searchParams.get("state"),
    ]) {
      expect(canary).toBeTruthy();
      expect(captured).not.toContain(canary);
    }
    expect(output.mock.calls).toHaveLength(9);
    const record: unknown = output.mock.calls.at(-1)?.[0];
    expect(record).toEqual({
      request_id: failed.headers.get("x-request-id"),
      route: "events",
      method: "GET",
      status: 503,
      duration_ms: expect.any(Number) as unknown,
      error_code: "dependency_unavailable",
      retry_after: failed.headers.get("retry-after"),
    });
    expect(errors).not.toHaveBeenCalled();
  });

  it.each(["disconnect", "deleteAccount"] as const)(
    "attaches %s revocation to the Worker lifetime after local deletion",
    async (operation) => {
      const credential = await signIn();
      const connected = await grant("/v1/connections/google/start", credential);
      const connectionId = (await connected.response.json<{ connection_id: string }>())
        .connection_id;
      const ctx = createExecutionContext();
      const background = vi.spyOn(ctx, "waitUntil");
      const originalFetch = globalThis.fetch;
      vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
        const url =
          input instanceof Request ? input.url : input instanceof URL ? input.href : input;
        if (url.endsWith("/revoke")) return Promise.reject(new Error("canary-revocation-failure"));
        return originalFetch(input, init);
      });
      const path = operation === "disconnect" ? `/v1/connections/${connectionId}` : "/v1/account";
      const response = await worker.fetch(
        new Request(`http://127.0.0.1:8787${path}`, {
          method: "DELETE",
          headers: { authorization: `Bearer ${credential}` },
        }),
        bindings,
        ctx,
      );
      expect(response.status).toBe(204);
      expect(background).toHaveBeenCalledTimes(1);
      expect(
        await bindings.DB.prepare("SELECT id FROM connections WHERE id = ?")
          .bind(connectionId)
          .first(),
      ).toBeNull();
      await expect(waitOnExecutionContext(ctx)).resolves.toBeUndefined();
      if (operation === "deleteAccount") {
        expect(await bindings.DB.prepare("SELECT id FROM principals").first()).toBeNull();
        expect(
          await bindings.DB.prepare("SELECT identity_digest FROM identity_deletion_fences").first(),
        ).not.toBeNull();
      }
    },
  );
});
