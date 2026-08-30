import { describe, expect, it } from "vitest";

import { ROUTE_NAMES, type RouteName } from "../../src/contracts";
import { ContractError, errorResponse } from "../../src/http/responses";
import {
  createRouter,
  type RouteHandler,
  type RouteHandlers,
  type RouteInput,
} from "../../src/http/router";

const id = "550e8400-e29b-41d4-a716-446655440000";
const transactionId = "t".repeat(43);
const deviceId = "d".repeat(22);
const pollingSecret = "p".repeat(43);
const credential = `v1.${deviceId}.${"s".repeat(43)}`;
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

function jsonRequest(path: string, body: unknown, contentType = "application/json"): Request {
  return new Request(`https://calendar.test${path}`, {
    method: "POST",
    headers: { "content-type": contentType },
    body: JSON.stringify(body),
  });
}

const startBody = {
  client_kind: "web",
  device_name: "Browser",
  code_challenge: "a".repeat(43),
};

describe("contract router", () => {
  it("exact-matches method and path and returns a generic 404", async () => {
    const route = createRouter(handlers());
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
    const route = createRouter(
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
    const route = createRouter(
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

  it("enforces JSON media type and actual body bytes", async () => {
    const route = createRouter(handlers());
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
  });

  it("rejects duplicate and unknown queries before invoking a handler", async () => {
    const route = createRouter(handlers());
    const base = `/v1/calendars/${id}/events`;
    const range = "start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z";
    expect(
      (
        await route(
          new Request(`https://calendar.test${base}?${range}&start=2026-01-01T00%3A00%3A00Z`),
        )
      ).status,
    ).toBe(400);
    expect((await route(new Request(`https://calendar.test${base}?${range}&other=x`))).status).toBe(
      400,
    );
  });

  it("enforces UUID paths and a single bounded calendar range", async () => {
    const route = createRouter(handlers());
    expect(
      (
        await route(
          new Request(
            "https://calendar.test/v1/calendars/not-an-id/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z",
          ),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await route(
          new Request(
            `https://calendar.test/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-04-05T00%3A00%3A00Z`,
          ),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await route(
          new Request(
            `https://calendar.test/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`,
          ),
        )
      ).status,
    ).toBe(200);
  });

  it("distinguishes malformed client input from handler invariant failures", async () => {
    const route = createRouter(
      handlers({ healthLive: () => Promise.resolve({ status: "wrong" }) }),
    );
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
    const route = createRouter(
      handlers({ events: () => Promise.reject(new ContractError("dependency_unavailable", 900)) }),
    );
    const response = await route(
      new Request(
        `https://calendar.test/v1/calendars/${id}/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z`,
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
    const response = await createRouter(handlers())(
      new Request(`https://calendar.test/v1/devices/${deviceId}`, { method: "DELETE" }),
    );
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
});
