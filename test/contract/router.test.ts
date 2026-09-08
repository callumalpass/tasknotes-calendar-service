import { describe, expect, it, vi } from "vitest";

import { ROUTE_NAMES, type RouteName } from "../../src/contracts";
import { ContractError, errorResponse } from "../../src/http/responses";
import {
  createRouter,
  type RouteHandler,
  type RouteHandlers,
  type RouteInput,
  type RouterAuthentication,
} from "../../src/http/router";

const id = "550e8400-e29b-41d4-a716-446655440000";
const transactionId = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8";
const deviceId = "AAECAwQFBgcICQoLDA0ODw";
const pollingSecret = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
const credential = "v1.AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8";
const instant = "2026-08-30T12:00:00Z";

const validOutputs: Readonly<Record<RouteName, unknown>> = {
  healthLive: { status: "ok" },
  healthReady: { status: "ready" },
  signInStart: {
    transaction_id: transactionId,
    authorization_url: "https://accounts.example/authorize",
    polling_secret: pollingSecret,
    expires_at: instant,
  },
  signInStatus: { status: "pending", expires_at: instant },
  signInRedeem: {
    session: {
      credential,
      session_id: deviceId,
      idle_expires_at: instant,
      absolute_expires_at: instant,
    },
  },
  connectStart: {
    transaction_id: transactionId,
    authorization_url: "https://accounts.example/authorize",
    polling_secret: pollingSecret,
    expires_at: instant,
  },
  connectStatus: { status: "authorized", expires_at: instant },
  connectRedeem: { connection_id: id, status: "active" },
  session: {
    principal_id: id,
    session_id: deviceId,
    client_kind: "web",
    device_name: "Browser",
    created_at: instant,
    idle_expires_at: instant,
    absolute_expires_at: instant,
  },
  connections: { connections: [] },
  disconnect: undefined,
  calendars: { calendars: [] },
  events: { events: [], next_cursor: null },
  devices: { devices: [] },
  revokeDevice: undefined,
  deleteAccount: undefined,
  providerCallback: { status: "complete" },
};

function handlers(overrides: Partial<Record<RouteName, RouteHandler>> = {}): RouteHandlers {
  return Object.fromEntries(
    ROUTE_NAMES.map((name) => [
      name,
      overrides[name] ?? (() => Promise.resolve(validOutputs[name])),
    ]),
  ) as unknown as RouteHandlers;
}

function authenticateSuccessfully(value: string) {
  return Promise.resolve(
    value === credential
      ? {
          principalId: id,
          session: {
            id: deviceId,
            deviceName: "Browser",
            clientKind: "web" as const,
            createdAt: instant,
            lastUsedAt: instant,
            idleExpiresAt: instant,
            absoluteExpiresAt: instant,
            revokedAt: null,
          },
        }
      : null,
  );
}

function successfulAuthentication(): RouterAuthentication {
  return { authenticate: authenticateSuccessfully };
}

function router(
  routeHandlers: RouteHandlers = handlers(),
  authentication: RouterAuthentication = successfulAuthentication(),
): (request: Request) => Promise<Response> {
  return createRouter(routeHandlers, authentication);
}

function jsonRequest(
  path: string,
  body: unknown,
  contentType = "application/json",
  authenticated = false,
): Request {
  const headers = new Headers({ "content-type": contentType });
  if (authenticated) headers.set("authorization", `Bearer ${credential}`);
  return new Request(`https://calendar.test${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function authenticatedRequest(path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${credential}`);
  return new Request(`https://calendar.test${path}`, { ...init, headers });
}

const startBody = {
  client_kind: "web",
  device_name: "Browser",
  code_challenge: "A".repeat(43),
};

const generic401 = {
  code: "authentication_required",
  message: "Authentication is required.",
};

const authenticatedRouteCases: readonly {
  readonly name: RouteName;
  readonly validRequest: () => Request;
  readonly malformedRequest: () => Request;
}[] = [
  {
    name: "connectStart",
    validRequest: () => jsonRequest("/v1/connections/google/start", startBody, undefined, true),
    malformedRequest: () =>
      new Request("https://calendar.test/v1/connections/google/start", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "not-json",
      }),
  },
  {
    name: "connectStatus",
    validRequest: () =>
      jsonRequest(
        `/v1/connections/google/${transactionId}/status`,
        { polling_secret: pollingSecret },
        undefined,
        true,
      ),
    malformedRequest: () =>
      jsonRequest("/v1/connections/google/%/status", { polling_secret: pollingSecret }),
  },
  {
    name: "connectRedeem",
    validRequest: () =>
      jsonRequest(
        `/v1/connections/google/${transactionId}/redeem`,
        { polling_secret: pollingSecret, code_verifier: "v".repeat(43) },
        undefined,
        true,
      ),
    malformedRequest: () => jsonRequest(`/v1/connections/google/${transactionId}/redeem`, {}),
  },
  {
    name: "session",
    validRequest: () => authenticatedRequest("/v1/session"),
    malformedRequest: () => new Request("https://calendar.test/v1/session?unexpected=true"),
  },
  {
    name: "connections",
    validRequest: () => authenticatedRequest("/v1/connections"),
    malformedRequest: () => new Request("https://calendar.test/v1/connections?x=1&x=2"),
  },
  {
    name: "disconnect",
    validRequest: () => authenticatedRequest(`/v1/connections/${id}`, { method: "DELETE" }),
    malformedRequest: () =>
      new Request("https://calendar.test/v1/connections/not-a-uuid", { method: "DELETE" }),
  },
  {
    name: "calendars",
    validRequest: () => authenticatedRequest("/v1/calendars"),
    malformedRequest: () => new Request("https://calendar.test/v1/calendars?unexpected=true"),
  },
  {
    name: "events",
    validRequest: () =>
      authenticatedRequest(
        `/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`,
      ),
    malformedRequest: () =>
      new Request("https://calendar.test/v1/calendars/not-a-uuid/events?unexpected=true"),
  },
  {
    name: "devices",
    validRequest: () => authenticatedRequest("/v1/devices"),
    malformedRequest: () => new Request("https://calendar.test/v1/devices?unexpected=true"),
  },
  {
    name: "revokeDevice",
    validRequest: () => authenticatedRequest(`/v1/devices/${deviceId}`, { method: "DELETE" }),
    malformedRequest: () =>
      new Request("https://calendar.test/v1/devices/not-a-device", { method: "DELETE" }),
  },
  {
    name: "deleteAccount",
    validRequest: () => authenticatedRequest("/v1/account", { method: "DELETE" }),
    malformedRequest: () =>
      new Request("https://calendar.test/v1/account?unexpected=true", { method: "DELETE" }),
  },
];

describe("contract router", () => {
  it("exact-matches method and path and returns a generic 404", async () => {
    const route = router();
    for (const request of [
      new Request("https://calendar.test/health/live/"),
      new Request("https://calendar.test/v1/session", { method: "POST" }),
      new Request("https://calendar.test/v1/unknown"),
    ]) {
      const response = await route(request);
      expect(response.status).toBe(404);
      await expect(response.json()).resolves.toEqual({
        code: "resource_not_found",
        message: "Resource not found.",
      });
    }
  });

  it("parses a strict JSON body and passes only validated values", async () => {
    let received: RouteInput | undefined;
    const route = router(
      handlers({
        signInStart: (input) => {
          received = input;
          return Promise.resolve(validOutputs.signInStart);
        },
      }),
    );
    const response = await route(jsonRequest("/v1/sign-in/start", startBody));
    expect(response.status).toBe(201);
    expect(received?.body).toEqual(startBody);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");

    const invalid = await route(jsonRequest("/v1/sign-in/start", { ...startBody, extra: true }));
    expect(invalid.status).toBe(400);
  });

  it("keeps the polling capability out of status URLs", async () => {
    let received: RouteInput | undefined;
    const route = router(
      handlers({
        signInStatus: (input) => {
          received = input;
          return Promise.resolve(validOutputs.signInStatus);
        },
      }),
    );
    const response = await route(
      jsonRequest(`/v1/sign-in/${transactionId}/status`, { polling_secret: pollingSecret }),
    );

    expect(response.status).toBe(200);
    expect(received?.body).toEqual({ polling_secret: pollingSecret });
    expect(received?.query).toEqual({});
    expect(response.url).not.toContain(pollingSecret);
  });

  it("enforces JSON media type, declared length, and actual body bytes", async () => {
    const route = router();
    expect((await route(jsonRequest("/v1/sign-in/start", startBody, "text/plain"))).status).toBe(
      415,
    );
    expect(
      (
        await route(
          jsonRequest("/v1/sign-in/start", startBody, "application/json; charset=iso-8859-1"),
        )
      ).status,
    ).toBe(415);
    expect(
      (await route(jsonRequest("/v1/sign-in/start", { ...startBody, padding: "x".repeat(17_000) })))
        .status,
    ).toBe(413);

    for (const contentLength of ["invalid", "17000"]) {
      const request = jsonRequest("/v1/sign-in/start", startBody);
      request.headers.set("content-length", contentLength);
      expect((await route(request)).status).toBe(contentLength === "invalid" ? 400 : 413);
    }
    expect(
      (
        await route(
          new Request("https://calendar.test/v1/sign-in/start", {
            method: "POST",
            headers: { "content-type": "application/json" },
          }),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await route(
          new Request("https://calendar.test/v1/sign-in/start", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{",
          }),
        )
      ).status,
    ).toBe(400);
  });

  it("accepts an edge-normalized empty DELETE stream but rejects nonempty bytes", async () => {
    const disconnect = vi.fn(() => Promise.resolve(undefined));
    const route = router(handlers({ disconnect }));

    const empty = await route(
      authenticatedRequest(`/v1/connections/${id}`, { method: "DELETE", body: "" }),
    );
    expect(empty.status).toBe(204);
    expect(disconnect).toHaveBeenCalledTimes(1);

    const nonempty = await route(
      authenticatedRequest(`/v1/connections/${id}`, { method: "DELETE", body: "x" }),
    );
    expect(nonempty.status).toBe(400);

    for (const contentLength of ["invalid", "1"]) {
      const request = authenticatedRequest(`/v1/connections/${id}`, {
        method: "DELETE",
        body: "",
        headers: { "content-length": contentLength },
      });
      expect((await route(request)).status).toBe(400);
    }
    expect(disconnect).toHaveBeenCalledTimes(1);
  });

  it.each(authenticatedRouteCases)(
    "authenticates $name before parsing malformed path, query, or body input",
    async ({ name, malformedRequest }) => {
      const authenticate = vi.fn(authenticateSuccessfully);
      const handler = vi.fn(() => Promise.resolve(validOutputs[name]));
      const route = router(handlers({ [name]: handler }), { authenticate });

      for (const authorization of [
        undefined,
        "bearer not-a-service-credential",
        `Bearer ${credential.replace(/8$/, "9")}`,
      ]) {
        const request = malformedRequest();
        if (authorization !== undefined) request.headers.set("authorization", authorization);
        const response = await route(request);
        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toEqual(generic401);
      }

      expect(authenticate).not.toHaveBeenCalled();
      expect(handler).not.toHaveBeenCalled();
    },
  );

  it("returns the same generic 401 for wrong, revoked, and expired credentials", async () => {
    const rejectedCredentials = [
      credential.replace(/8$/, "A"),
      credential.replace(/8$/, "E"),
      credential.replace(/8$/, "I"),
    ];
    const authenticate = vi.fn(() => Promise.resolve(null));
    const handler = vi.fn(() => Promise.resolve(validOutputs.session));
    const route = router(handlers({ session: handler }), { authenticate });

    for (const rejected of rejectedCredentials) {
      const response = await route(
        new Request("https://calendar.test/v1/session", {
          headers: { authorization: `Bearer ${rejected}` },
        }),
      );
      expect(response.status).toBe(401);
      const text = await response.text();
      expect(JSON.parse(text)).toEqual(generic401);
      expect(text).not.toContain(rejected);
    }
    expect(authenticate).toHaveBeenCalledTimes(3);
    expect(handler).not.toHaveBeenCalled();
  });

  it.each(authenticatedRouteCases)(
    "authenticates $name once and injects only immutable principal and session context",
    async ({ name, validRequest }) => {
      let received: RouteInput | undefined;
      const authenticate = vi.fn(authenticateSuccessfully);
      const route = router(
        handlers({
          [name]: (input: RouteInput) => {
            received = input;
            return Promise.resolve(validOutputs[name]);
          },
        }),
        { authenticate },
      );

      const response = await route(validRequest());
      expect(response.status).toBeLessThan(400);
      expect(authenticate).toHaveBeenCalledOnce();
      expect(authenticate).toHaveBeenCalledWith(credential);
      expect(received?.authenticated).toEqual({
        principalId: id,
        sessionId: deviceId,
        session: {
          id: deviceId,
          deviceName: "Browser",
          clientKind: "web",
          createdAt: instant,
          lastUsedAt: instant,
          idleExpiresAt: instant,
          absoluteExpiresAt: instant,
          revokedAt: null,
        },
      });
      expect(Object.isFrozen(received?.authenticated)).toBe(true);
      expect(Object.isFrozen(received?.authenticated?.session)).toBe(true);
      expect(Object.isFrozen(received)).toBe(true);
      expect(JSON.stringify(received)).not.toContain(credential);
    },
  );

  it("maps authentication dependency failures to a generic internal error without leakage", async () => {
    const dependencyError = new ContractError("dependency_unavailable");
    dependencyError.message = `revoked credential ${credential} for a sensitive reason`;
    const authenticate = vi.fn(() => Promise.reject(dependencyError));
    const handler = vi.fn(() => Promise.resolve(validOutputs.session));
    const response = await router(handlers({ session: handler }), { authenticate })(
      authenticatedRequest("/v1/session"),
    );

    expect(response.status).toBe(500);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({
      code: "internal_error",
      message: "An internal error occurred.",
    });
    expect(text).not.toContain(credential);
    expect(text).not.toContain("revoked");
    expect(authenticate).toHaveBeenCalledOnce();
    expect(handler).not.toHaveBeenCalled();
  });

  it("rejects duplicate and combined Authorization values without authenticating", async () => {
    const authenticate = vi.fn(authenticateSuccessfully);
    const route = router(handlers(), { authenticate });
    const duplicateHeaders = new Headers();
    duplicateHeaders.append("authorization", `Bearer ${credential}`);
    duplicateHeaders.append("authorization", `Bearer ${credential}`);

    for (const headers of [
      duplicateHeaders,
      new Headers({ authorization: `Bearer ${credential},Bearer ${credential}` }),
    ]) {
      const response = await route(new Request("https://calendar.test/v1/session", { headers }));
      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual(generic401);
    }
    expect(authenticate).not.toHaveBeenCalled();
  });

  it("does not authenticate public routes or inject context when Authorization is supplied", async () => {
    const publicRequests: readonly [RouteName, () => Request][] = [
      ["healthLive", () => new Request("https://calendar.test/health/live")],
      ["healthReady", () => new Request("https://calendar.test/health/ready")],
      ["signInStart", () => jsonRequest("/v1/sign-in/start", startBody)],
      [
        "signInStatus",
        () => jsonRequest(`/v1/sign-in/${transactionId}/status`, { polling_secret: pollingSecret }),
      ],
      [
        "signInRedeem",
        () =>
          jsonRequest(`/v1/sign-in/${transactionId}/redeem`, {
            polling_secret: pollingSecret,
            code_verifier: "v".repeat(43),
          }),
      ],
      [
        "providerCallback",
        () =>
          new Request(
            `https://calendar.test/oauth/google/callback?code=${"c".repeat(16)}&state=${transactionId}`,
          ),
      ],
    ];
    const authenticate = vi.fn(authenticateSuccessfully);
    const received = new Map<RouteName, RouteInput>();
    const overrides = Object.fromEntries(
      publicRequests.map(([name]) => [
        name,
        (input: RouteInput) => {
          received.set(name, input);
          return Promise.resolve(validOutputs[name]);
        },
      ]),
    ) as Partial<Record<RouteName, RouteHandler>>;
    const route = router(handlers(overrides), { authenticate });

    for (const [name, makeRequest] of publicRequests) {
      const request = makeRequest();
      request.headers.set("authorization", `Bearer ${credential}`);
      expect((await route(request)).status, name).toBeLessThan(400);
      expect(received.get(name)).not.toHaveProperty("authenticated");
    }
    expect(authenticate).not.toHaveBeenCalled();
  });

  it("rejects duplicate and unknown queries before invoking a handler", async () => {
    const route = router();
    const base = `/v1/calendars/${id}/events`;
    const range = "start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z";
    expect(
      (await route(authenticatedRequest(`${base}?${range}&start=2026-01-01T00%3A00%3A00Z`))).status,
    ).toBe(400);
    expect((await route(authenticatedRequest(`${base}?${range}&other=x`))).status).toBe(400);
  });

  it("enforces UUID paths and a single bounded calendar range", async () => {
    const route = router();
    expect(
      (
        await route(
          authenticatedRequest(
            "/v1/calendars/not-an-id/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z",
          ),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await route(
          authenticatedRequest(
            `/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-04-05T00%3A00%3A00Z`,
          ),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await route(
          authenticatedRequest(
            `/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`,
          ),
        )
      ).status,
    ).toBe(200);
  });

  it("validates event tombstones and contains invalid event handler output", async () => {
    const path = `/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`;
    const tombstone = {
      id,
      calendar_id: id,
      status: "cancelled",
      title: null,
      description: null,
      location: null,
      start: null,
      end: null,
      updated_at: instant,
      recurrence: null,
    };
    const valid = await router(
      handlers({ events: () => Promise.resolve({ events: [tombstone], next_cursor: null }) }),
    )(authenticatedRequest(path));
    expect(valid.status).toBe(200);
    await expect(valid.json()).resolves.toEqual({ events: [tombstone], next_cursor: null });

    const invalid = await router(
      handlers({
        events: () =>
          Promise.resolve({
            events: [{ ...tombstone, start: { kind: "date", date: "2026-01-01" } }],
            next_cursor: null,
          }),
      }),
    )(authenticatedRequest(path));
    expect(invalid.status).toBe(500);
    await expect(invalid.json()).resolves.toEqual({
      code: "internal_error",
      message: "An internal error occurred.",
    });
  });

  it("distinguishes malformed client input from handler invariant failures", async () => {
    const route = router(handlers({ healthLive: () => Promise.resolve({ status: "wrong" }) }));
    const internal = await route(new Request("https://calendar.test/health/live"));
    expect(internal.status).toBe(500);
    await expect(internal.json()).resolves.toEqual({
      code: "internal_error",
      message: "An internal error occurred.",
    });

    const malformed = await route(
      jsonRequest("/v1/sign-in/start", { ...startBody, client_kind: "desktop" }),
    );
    expect(malformed.status).toBe(400);
    await expect(malformed.json()).resolves.toEqual({
      code: "invalid_request",
      message: "Request is invalid.",
    });
  });

  it("supports privacy-safe domain errors and bounded Retry-After", async () => {
    const route = router(
      handlers({ events: () => Promise.reject(new ContractError("dependency_unavailable", 900)) }),
    );
    const response = await route(
      authenticatedRequest(
        `/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`,
      ),
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("300");
    await expect(response.json()).resolves.toEqual({
      code: "dependency_unavailable",
      message: "Service is temporarily unavailable.",
    });

    expect(errorResponse("rate_limited", -10).headers.get("retry-after")).toBe("1");
    expect(errorResponse("invalid_request", 10).headers.get("retry-after")).toBeNull();
  });

  it("returns no body and privacy headers for destructive routes", async () => {
    const response = await router()(
      authenticatedRequest(`/v1/devices/${deviceId}`, { method: "DELETE" }),
    );
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
});
