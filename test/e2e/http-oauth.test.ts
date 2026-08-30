import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import type { Env } from "../../src/env";
import type { FakeGoogleConfiguration, FakeGoogleStats } from "../support/fake-google";

const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher };
const fake = bindings.FAKE_GOOGLE;
const verifier = "tasknotes-http-e2e-verifier-abcdefghijklmnopqrstuvwxyz0123456789";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function challenge(value = verifier): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
  );
}

async function api(path: string, init: RequestInit = {}, credential?: string): Promise<Response> {
  const headers = new Headers(init.headers);
  if (credential !== undefined) headers.set("authorization", `Bearer ${credential}`);
  return exports.default.fetch(new Request(`http://127.0.0.1:8787${path}`, { ...init, headers }));
}

async function post(path: string, value: unknown, credential?: string): Promise<Response> {
  return api(
    path,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    },
    credential,
  );
}

async function control(path: string, init?: RequestInit): Promise<Response> {
  return fake.fetch(`https://fake-google-control.test${path}`, init);
}

async function configure(value: FakeGoogleConfiguration): Promise<void> {
  expect(
    (
      await control("/configure", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(value),
      })
    ).status,
  ).toBe(204);
}

async function stats(): Promise<FakeGoogleStats> {
  return (await control("/stats")).json<FakeGoogleStats>();
}

interface Started {
  transaction_id: string;
  authorization_url: string;
  polling_secret: string;
  expires_at: string;
}

async function start(path: string, credential?: string, name = "E2E Browser"): Promise<Started> {
  const response = await post(
    path,
    { client_kind: "web", device_name: name, code_challenge: await challenge() },
    credential,
  );
  expect(response.status).toBe(201);
  return response.json<Started>();
}

async function authorize(started: Started): Promise<URL> {
  const response = await fake.fetch(new Request(started.authorization_url, { redirect: "manual" }));
  expect(response.status).toBe(302);
  return new URL(response.headers.get("location") ?? "missing:");
}

async function callback(location: URL): Promise<Response> {
  return exports.default.fetch(new Request(location));
}

interface SignedIn {
  credential: string;
  session_id: string;
  principalId: string;
}

async function signIn(name = "E2E Browser"): Promise<SignedIn> {
  const started = await start("/v1/sign-in/start", undefined, name);
  const location = await authorize(started);
  const callbackResponse = await callback(location);
  expect(callbackResponse.status).toBe(200);
  await expect(callbackResponse.json()).resolves.toEqual({ status: "complete" });
  const status = await post(`/v1/sign-in/${started.transaction_id}/status`, {
    polling_secret: started.polling_secret,
  });
  await expect(status.json()).resolves.toMatchObject({ status: "authorized" });
  const redeemed = await post(`/v1/sign-in/${started.transaction_id}/redeem`, {
    polling_secret: started.polling_secret,
    code_verifier: verifier,
  });
  expect(redeemed.status).toBe(200);
  const value = await redeemed.json<{ session: { credential: string; session_id: string } }>();
  const current = await api("/v1/session", {}, value.session.credential);
  expect(current.status).toBe(200);
  const session = await current.json<{ principal_id: string }>();
  return {
    credential: value.session.credential,
    session_id: value.session.session_id,
    principalId: session.principal_id,
  };
}

async function connect(
  credential: string,
): Promise<{ id: string; started: Started; callbackLocation: URL }> {
  const started = await start("/v1/connections/google/start", credential, "Calendar consent");
  const location = await authorize(started);
  expect((await callback(location)).status).toBe(200);
  const status = await post(
    `/v1/connections/google/${started.transaction_id}/status`,
    { polling_secret: started.polling_secret },
    credential,
  );
  await expect(status.json()).resolves.toMatchObject({ status: "authorized" });
  const response = await post(
    `/v1/connections/google/${started.transaction_id}/redeem`,
    { polling_secret: started.polling_secret, code_verifier: verifier },
    credential,
  );
  expect(response.status).toBe(200);
  const result = await response.json<{ connection_id: string }>();
  return { id: result.connection_id, started, callbackLocation: location };
}

beforeEach(async () => {
  expect((await control("/reset", { method: "POST" })).status).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

describe("Worker HTTP OAuth and account slice", () => {
  it("completes browser sign-in and keeps sign-in independent of Calendar grants", async () => {
    const signedIn = await signIn();
    const session = await api("/v1/session", {}, signedIn.credential);
    await expect(session.json()).resolves.toMatchObject({
      principal_id: signedIn.principalId,
      session_id: signedIn.session_id,
      client_kind: "web",
      device_name: "E2E Browser",
    });
    await expect(
      api("/v1/connections", {}, signedIn.credential).then((r) => r.json()),
    ).resolves.toEqual({
      connections: [],
    });
    expect(await bindings.DB.prepare("SELECT COUNT(*) AS count FROM connections").first()).toEqual({
      count: 0,
    });
    expect(await stats()).toMatchObject({ tokenRequests: 1, revokeCalls: 0, calendarCalls: 0 });
  });

  it("keys principals by subject rather than email", async () => {
    await configure({ subject: "subject-one", email: "same@example.test" });
    const first = await signIn("First");
    await configure({ subject: "subject-one", email: "changed@example.test" });
    const second = await signIn("Second");
    expect(second.principalId).toBe(first.principalId);

    await configure({ subject: "subject-two", email: "same@example.test" });
    const third = await signIn("Third");
    expect(third.principalId).not.toBe(first.principalId);
  });

  it("connects, replaces one encrypted connection, disconnects, and never calls Calendar reads", async () => {
    const signedIn = await signIn();
    const first = await connect(signedIn.credential);
    const firstRow = await bindings.DB.prepare(
      "SELECT id, generation, token_version, ciphertext FROM connections WHERE id = ?",
    )
      .bind(first.id)
      .first<{ id: string; generation: number; token_version: number; ciphertext: string }>();
    expect(firstRow).toMatchObject({ id: first.id, generation: 1, token_version: 1 });
    expect(firstRow?.ciphertext).not.toContain("fake-refresh-token");
    const persisted = JSON.stringify({
      transactions: (await bindings.DB.prepare("SELECT * FROM oauth_transactions").all()).results,
      connections: (await bindings.DB.prepare("SELECT * FROM connections").all()).results,
      identities: (await bindings.DB.prepare("SELECT * FROM external_identities").all()).results,
      sessions: (await bindings.DB.prepare("SELECT * FROM device_sessions").all()).results,
    });
    const authorization = new URL(first.started.authorization_url);
    for (const secret of [
      authorization.searchParams.get("state"),
      first.callbackLocation.searchParams.get("code"),
      first.started.polling_secret,
      verifier,
      "fake-access-token-000000000000000000000001",
      "fake-refresh-token-000000000000000000001",
    ]) {
      expect(secret).not.toBeNull();
      expect(persisted).not.toContain(secret ?? "impossible-null-secret");
    }

    await bindings.DB.prepare(
      `UPDATE connections SET discovery_lease_owner = 'replacement-race-owner',
         discovery_lease_until = unixepoch() + 45,
         discovery_lease_generation = generation,
         discovery_lease_token_version = token_version, updated_at = unixepoch()
       WHERE id = ?`,
    )
      .bind(first.id)
      .run();
    const second = await connect(signedIn.credential);
    expect(second.id).toBe(first.id);
    expect(
      await bindings.DB.prepare(
        `SELECT generation, token_version, discovery_lease_owner
         FROM connections WHERE id = ?`,
      )
        .bind(first.id)
        .first(),
    ).toEqual({ generation: 2, token_version: 2, discovery_lease_owner: null });
    const listed = await api("/v1/connections", {}, signedIn.credential);
    await expect(listed.json()).resolves.toMatchObject({
      connections: [{ id: first.id, provider: "google", status: "active" }],
    });

    const unavailableCalendars = await api("/v1/calendars", {}, signedIn.credential);
    expect(unavailableCalendars.status).toBe(503);
    await expect(unavailableCalendars.json()).resolves.toMatchObject({
      code: "dependency_unavailable",
    });
    const unknownCalendar = await api(
      "/v1/calendars/550e8400-e29b-41d4-a716-446655440000/events?start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z",
      {},
      signedIn.credential,
    );
    expect(unknownCalendar.status).toBe(404);
    await expect(unknownCalendar.json()).resolves.toMatchObject({ code: "resource_not_found" });
    expect((await stats()).calendarCalls).toBe(0);

    const disconnected = await api(
      `/v1/connections/${first.id}`,
      { method: "DELETE" },
      signedIn.credential,
    );
    expect(disconnected.status).toBe(204);
    expect(await bindings.DB.prepare("SELECT 1 FROM connections").first()).toBeNull();
    expect(await stats()).toMatchObject({ revokeCalls: 1, calendarCalls: 0 });
    expect(
      (await api(`/v1/connections/${first.id}`, { method: "DELETE" }, signedIn.credential)).status,
    ).toBe(404);
  });

  it("contains provider denials and invalid OIDC responses behind quiet callbacks", async () => {
    for (const authorization of ["access_denied", "unknown_error"] as const) {
      await configure({ authorization });
      const started = await start("/v1/sign-in/start");
      const location = await authorize(started);
      const response = await callback(location);
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ status: "complete" });
      const status = await post(`/v1/sign-in/${started.transaction_id}/status`, {
        polling_secret: started.polling_secret,
      });
      await expect(status.json()).resolves.toMatchObject({
        status: "failed",
        failure_code: authorization === "access_denied" ? "access_denied" : "authorization_failed",
      });
    }

    for (const token of [
      "wrong_nonce",
      "wrong_issuer",
      "wrong_audience",
      "wrong_signature",
      "omitted_scope",
      "rate_limited",
    ] as const) {
      const started = await start("/v1/sign-in/start");
      const location = await authorize(started);
      await configure({ token });
      const response = await callback(location);
      expect(response.status).toBe(200);
      expect(await response.text()).toBe('{"status":"complete"}');
      const status = await post(`/v1/sign-in/${started.transaction_id}/status`, {
        polling_secret: started.polling_secret,
      });
      await expect(status.json()).resolves.toMatchObject({
        status: "failed",
        failure_code: "authorization_failed",
      });
    }

    const signedIn = await signIn("Calendar failure owner");
    for (const token of ["missing_refresh_token", "writable_scope"] as const) {
      const started = await start("/v1/connections/google/start", signedIn.credential);
      const location = await authorize(started);
      await configure({ token });
      expect((await callback(location)).status).toBe(200);
      const status = await post(
        `/v1/connections/google/${started.transaction_id}/status`,
        { polling_secret: started.polling_secret },
        signedIn.credential,
      );
      await expect(status.json()).resolves.toMatchObject({
        status: "failed",
        failure_code: "authorization_failed",
      });
    }
  });

  it("allows only one callback exchange and one redemption under HTTP concurrency", async () => {
    const started = await start("/v1/sign-in/start");
    const location = await authorize(started);
    const callbacks = await Promise.all(
      Array.from({ length: 20 }, () => callback(new URL(location.href))),
    );
    expect(callbacks.every((response) => response.status === 200)).toBe(true);
    expect(await stats()).toMatchObject({ uniqueCodeExchanges: 1, tokenRequests: 1 });

    const redemptions = await Promise.all(
      Array.from({ length: 20 }, () =>
        post(`/v1/sign-in/${started.transaction_id}/redeem`, {
          polling_secret: started.polling_secret,
          code_verifier: verifier,
        }),
      ),
    );
    expect(redemptions.filter((response) => response.status === 200)).toHaveLength(1);
    expect(redemptions.filter((response) => response.status === 409)).toHaveLength(19);
  });

  it("discovers once concurrently and reads uncached normalized event pages", async () => {
    await configure({
      calendarEnabled: true,
      calendarDelayMs: 1_500,
      calendarPages: [
        {
          items: [
            {
              id: "private-provider-calendar-id",
              summary: "Work",
              description: "Current schedule",
              timeZone: "Europe/London",
              accessRole: "owner",
              primary: true,
            },
            {
              id: "private-provider-calendar-deleted",
              summary: "Temporary",
              accessRole: "reader",
            },
          ],
        },
      ],
      eventPages: [
        {
          calendarId: "private-provider-calendar-id",
          nextPageToken: "second-page",
          items: [
            {
              id: "private-event-id",
              status: "confirmed",
              updated: "2026-01-01T10:00:00Z",
              summary: "Timed",
              start: { dateTime: "2026-01-02T10:00:00Z" },
              end: { dateTime: "2026-01-02T11:00:00Z" },
            },
            {
              id: "private-all-day-id",
              status: "confirmed",
              updated: "2026-01-01T10:00:00Z",
              start: { date: "2026-01-03" },
              end: { date: "2026-01-04" },
            },
          ],
        },
        {
          calendarId: "private-provider-calendar-id",
          items: [
            {
              id: "private-tombstone-id",
              status: "cancelled",
              updated: "2026-01-02T10:00:00Z",
              recurringEventId: "private-series-id",
              originalStartTime: { dateTime: "2026-01-04T10:00:00Z" },
            },
          ],
        },
      ],
    });
    const signedIn = await signIn("Live calendar");
    await connect(signedIn.credential);
    const discoveries = await Promise.all(
      Array.from({ length: 20 }, () => api("/v1/calendars", {}, signedIn.credential)),
    );
    expect(discoveries.every((response) => response.status === 200)).toBe(true);
    const calendars = await discoveries[0]?.json<{
      calendars: { id: string; name: string; color: null }[];
    }>();
    expect(calendars?.calendars).toHaveLength(2);
    const discoveredWork = calendars?.calendars.find((calendar) => calendar.name === "Work");
    expect(discoveredWork).toMatchObject({ name: "Work", color: null });
    expect((await stats()).calendarListCalls).toBe(1);

    await configure({
      calendarDelayMs: 0,
      calendarPages: [
        {
          items: [
            {
              id: "private-provider-calendar-id",
              summary: "Work renamed",
              description: "Updated schedule",
              timeZone: "Europe/London",
              accessRole: "owner",
              primary: true,
            },
          ],
        },
      ],
    });
    const rediscovered = await api("/v1/calendars", {}, signedIn.credential);
    expect(rediscovered.status).toBe(200);
    const rediscoveredValue = await rediscovered.json<{
      calendars: { id: string; name: string }[];
    }>();
    expect(rediscoveredValue.calendars).toEqual([
      { ...rediscoveredValue.calendars[0], id: discoveredWork?.id, name: "Work renamed" },
    ]);
    expect((await stats()).calendarListCalls).toBe(2);

    const publicId = discoveredWork?.id ?? "missing";
    const range = "start=2026-01-01T00%3A00%3A00Z&end=2026-02-01T00%3A00%3A00Z";
    await configure({ calendar: "unauthorized" });
    const first = await api(`/v1/calendars/${publicId}/events?${range}`, {}, signedIn.credential);
    expect(first.status).toBe(200);
    expect(await stats()).toMatchObject({ refreshRequests: 1, eventCalls: 2 });
    expect(await bindings.DB.prepare("SELECT token_version FROM connections").first()).toEqual({
      token_version: 2,
    });
    const firstPage = await first.json<{ events: unknown[]; next_cursor: string }>();
    expect(firstPage.events).toHaveLength(2);
    expect(JSON.stringify(firstPage)).not.toContain("private-");
    const second = await api(
      `/v1/calendars/${publicId}/events?${range}&cursor=${encodeURIComponent(firstPage.next_cursor)}`,
      {},
      signedIn.credential,
    );
    expect(second.status).toBe(200);
    const secondPage = await second.json<{ events: unknown[]; next_cursor: null }>();
    expect(secondPage.events).toHaveLength(1);
    expect(secondPage.next_cursor).toBeNull();
    expect(JSON.stringify(secondPage)).not.toContain("private-");
    expect(
      await bindings.DB.prepare("SELECT name FROM sqlite_master WHERE name LIKE '%event%'").all(),
    ).toMatchObject({ results: [] });
  });

  it("lists and principal-binds devices, then account deletion invalidates the credential", async () => {
    const first = await signIn("First device");
    const second = await signIn("Second device");
    expect(second.principalId).toBe(first.principalId);
    const devices = await api("/v1/devices", {}, first.credential);
    const listed = await devices.json<{ devices: { id: string; current: boolean }[] }>();
    expect(listed.devices).toHaveLength(2);
    expect(listed.devices.find((device) => device.id === first.session_id)?.current).toBe(true);
    expect(
      (await api(`/v1/devices/${second.session_id}`, { method: "DELETE" }, first.credential))
        .status,
    ).toBe(204);
    expect((await api("/v1/session", {}, second.credential)).status).toBe(401);

    await connect(first.credential);
    const revocationsBeforeDeletion = (await stats()).revokeCalls;
    expect((await api("/v1/account", { method: "DELETE" }, first.credential)).status).toBe(204);
    expect((await api("/v1/session", {}, first.credential)).status).toBe(401);
    expect((await stats()).revokeCalls).toBe(revocationsBeforeDeletion + 1);
  });
});
