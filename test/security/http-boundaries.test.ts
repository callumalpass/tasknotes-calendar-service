import { createExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import { GoogleAccessTokens } from "../../src/connections/google-access-tokens";
import { createHandlers } from "../../src/http/handlers";
import { runtimeConfiguration } from "../../src/runtime/configuration";
import type { Env } from "../../src/env";
import type { FakeGoogleConfiguration, FakeGoogleStats } from "../support/fake-google";

const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher };
const fake = bindings.FAKE_GOOGLE;
const verifier = "security-http-verifier-abcdefghijklmnopqrstuvwxyz0123456789";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function challenge(): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
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
    await control("/configure", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    }),
  ).toHaveProperty("status", 204);
}

async function statistics(): Promise<FakeGoogleStats> {
  return (await control("/stats")).json<FakeGoogleStats>();
}

interface Started {
  transaction_id: string;
  authorization_url: string;
  polling_secret: string;
}

async function start(path: string, credential?: string): Promise<Started> {
  const response = await post(
    path,
    { client_kind: "web", device_name: "Security browser", code_challenge: await challenge() },
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

async function signIn(subject: string): Promise<{ credential: string; sessionId: string }> {
  await configure({ subject, email: "same-security@example.test" });
  const started = await start("/v1/sign-in/start");
  const callbackResponse = await exports.default.fetch(new Request(await authorize(started)));
  expect(callbackResponse.status).toBe(200);
  const confirmationCode = /class="code"[^>]*>([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})</u.exec(
    await callbackResponse.text(),
  )?.[1];
  const response = await post(`/v1/sign-in/${started.transaction_id}/redeem`, {
    polling_secret: started.polling_secret,
    code_verifier: verifier,
    confirmation_code: confirmationCode,
  });
  expect(response.status).toBe(200);
  const value = await response.json<{ session: { credential: string; session_id: string } }>();
  return { credential: value.session.credential, sessionId: value.session.session_id };
}

async function connect(credential: string): Promise<{ id: string; started: Started }> {
  const started = await start("/v1/connections/google/start", credential);
  expect((await exports.default.fetch(new Request(await authorize(started)))).status).toBe(200);
  const response = await post(
    `/v1/connections/google/${started.transaction_id}/redeem`,
    { polling_secret: started.polling_secret, code_verifier: verifier },
    credential,
  );
  expect(response.status).toBe(200);
  return { id: (await response.json<{ connection_id: string }>()).connection_id, started };
}

beforeEach(async () => {
  expect((await control("/reset", { method: "POST" })).status).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

describe("Worker HTTP security boundaries", () => {
  it("pins callback origin and exact path before consuming provider authority", async () => {
    const started = await start("/v1/sign-in/start");
    const callback = await authorize(started);
    const hostile = [
      new URL(callback.href.replace("http://127.0.0.1:8787", "http://attacker.test")),
      new URL(callback.href.replace(":8787", ":8788")),
      new URL(callback.href.replace("http://", "https://")),
      new URL(callback.href.replace("/oauth/google/callback", "/oauth/google/callback/")),
    ];
    const duplicate = new URL(callback);
    duplicate.searchParams.append("state", callback.searchParams.get("state") ?? "");
    const unknown = new URL(callback);
    unknown.searchParams.set("unrelated", "private-value");

    for (const url of hostile) {
      const response = await exports.default.fetch(new Request(url));
      expect(response.status).toBe(404);
    }
    for (const url of [duplicate]) {
      const response = await exports.default.fetch(new Request(url));
      expect(response.status).toBe(400);
    }
    expect(await statistics()).toMatchObject({ tokenRequests: 0, uniqueCodeExchanges: 0 });

    expect((await exports.default.fetch(new Request(unknown))).status).toBe(200);
    expect(await statistics()).toMatchObject({ tokenRequests: 1, uniqueCodeExchanges: 1 });
  });

  it("requires the browser-only confirmation and terminally rejects one wrong guess", async () => {
    const started = await start("/v1/sign-in/start");
    const location = await authorize(started);
    location.searchParams.set("hd", "example.test");
    location.searchParams.append("hd", "ignored.example.test");
    const callbackResponse = await exports.default.fetch(new Request(location));
    expect(callbackResponse.status).toBe(200);
    expect(callbackResponse.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(callbackResponse.headers.get("cache-control")).toBe("no-store");
    const html = await callbackResponse.text();
    const code = /class="code"[^>]*>([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})</u.exec(html)?.[1];
    expect(code).toBeDefined();
    const nonce = /<style nonce="([^"]+)"/u.exec(html)?.[1];
    expect(callbackResponse.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(callbackResponse.headers.get("content-security-policy")).toContain(
      `style-src 'nonce-${nonce}'`,
    );
    expect(html).not.toMatch(/<script|<link|https?:|v1\./u);
    const stored = await bindings.DB.prepare(
      "SELECT confirmation_code_hash FROM oauth_transactions WHERE id = ?",
    )
      .bind(started.transaction_id)
      .first<{ confirmation_code_hash: string }>();
    expect(stored?.confirmation_code_hash).toHaveLength(43);
    expect(stored?.confirmation_code_hash).not.toBe(code);
    const path = `/v1/sign-in/${started.transaction_id}/redeem`;
    const proof = { polling_secret: started.polling_secret, code_verifier: verifier };
    expect((await post(path, proof)).status).toBe(400);
    const status = await post(`/v1/sign-in/${started.transaction_id}/status`, {
      polling_secret: started.polling_secret,
    });
    expect(await status.text()).not.toContain(code);
    const wrongCode = code === "22222222" ? "33333333" : "22222222";
    expect((await post(path, { ...proof, confirmation_code: wrongCode })).status).toBe(409);
    expect((await post(path, { ...proof, confirmation_code: code })).status).toBe(409);
    expect(
      await bindings.DB.prepare("SELECT COUNT(*) FROM device_sessions").first("COUNT(*)"),
    ).toBe(0);
    expect((await exports.default.fetch(new Request(location))).status).toBe(200);
    expect(await (await exports.default.fetch(new Request(location))).text()).not.toContain(
      'class="code"',
    );
  });

  it("redeems confirmation once and never shows it on callback replay", async () => {
    const started = await start("/v1/sign-in/start");
    const location = await authorize(started);
    const html = await (await exports.default.fetch(new Request(location))).text();
    const code = /class="code"[^>]*>([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})</u.exec(html)?.[1];
    expect(code).toBeDefined();
    const path = `/v1/sign-in/${started.transaction_id}/redeem`;
    const proof = {
      polling_secret: started.polling_secret,
      code_verifier: verifier,
      confirmation_code: code,
    };
    expect((await post(path, proof)).status).toBe(200);
    expect((await post(path, proof)).status).toBe(409);
    expect(await (await exports.default.fetch(new Request(location))).text()).not.toContain(
      'class="code"',
    );
  });

  it("signs in a second device when Google returns already granted Calendar scopes", async () => {
    const first = await signIn("second-device-subject");
    await configure({ token: "granted_calendar_scopes" });
    const second = await signIn("second-device-subject");
    expect(second.sessionId).not.toBe(first.sessionId);
    const firstSession = await (
      await api("/v1/session", {}, first.credential)
    ).json<{ principal_id: string }>();
    const secondSession = await (
      await api("/v1/session", {}, second.credential)
    ).json<{ principal_id: string }>();
    expect(firstSession.principal_id).toBe(secondSession.principal_id);
    expect(await bindings.DB.prepare("SELECT COUNT(*) FROM connections").first("COUNT(*)")).toBe(0);
    expect(
      await bindings.DB.prepare("SELECT COUNT(*) FROM device_sessions").first("COUNT(*)"),
    ).toBe(2);
  });

  it("disconnects even when a real refresh rotates tokens after its authority read", async () => {
    const owner = await signIn("refresh-disconnect-owner");
    const connection = await connect(owner.credential);
    const runtime = await runtimeConfiguration(bindings);
    const authenticated = await runtime.deviceSessions.authenticate(owner.credential);
    if (authenticated === null) throw new Error("Missing fixture session");
    const tokens = new GoogleAccessTokens({
      db: bindings.DB,
      environment: runtime.environment,
      googleClientId: bindings.GOOGLE_CLIENT_ID,
      googleClientSecret: bindings.GOOGLE_CLIENT_SECRET,
      tokenKeyring: runtime.tokenKeyring,
      googleProvider: runtime.googleProvider,
      fetch: runtime.outboundFetch,
      random: { bytes: (length) => crypto.getRandomValues(new Uint8Array(length)) },
      sleep: () => Promise.resolve(),
    });
    const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
      new Proxy(statement, {
        get(target, property): unknown {
          if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
          if (property === "first")
            return async () => {
              const snapshot = await tokens.loadForPrincipal(authenticated.principalId);
              if (snapshot === null) throw new Error("Missing fixture connection");
              await tokens.access(snapshot, { forceRefresh: true });
              return target.first();
            };
          const value: unknown = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    const db = new Proxy(bindings.DB, {
      get(target, property): unknown {
        if (property === "prepare")
          return (sql: string) => {
            const statement = target.prepare(sql);
            return sql.startsWith("DELETE FROM connections WHERE id") ? wrap(statement) : statement;
          };
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const handlers = createHandlers({ ...bindings, DB: db });
    await expect(
      handlers.disconnect(
        {
          params: { connection_id: connection.id },
          query: {},
          authenticated: {
            principalId: authenticated.principalId,
            sessionId: authenticated.session.id,
            session: authenticated.session,
          },
        },
        new Request("http://127.0.0.1:8787"),
        createExecutionContext(),
      ),
    ).resolves.toBeUndefined();
    expect(await bindings.DB.prepare("SELECT COUNT(*) FROM connections").first("COUNT(*)")).toBe(0);
    expect(await statistics()).toMatchObject({ refreshRequests: 1 });
  });

  it("fences local disconnect despite corrupt token custody under concurrency", async () => {
    const owner = await signIn("disconnect-owner");
    const connection = await connect(owner.credential);
    const validationTrigger = await bindings.DB.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'connections_validate_update'",
    ).first<{ sql: string }>();
    if (validationTrigger === null) throw new Error("expected connection validation trigger");
    await bindings.DB.prepare("DROP TRIGGER connections_validate_update").run();
    await bindings.DB.prepare("UPDATE connections SET ciphertext = 'corrupt' WHERE id = ?")
      .bind(connection.id)
      .run();
    await bindings.DB.prepare(validationTrigger.sql).run();

    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        api(`/v1/connections/${connection.id}`, { method: "DELETE" }, owner.credential),
      ),
    );
    expect(responses.filter((response) => response.status === 204)).toHaveLength(1);
    expect(responses.every((response) => [204, 404, 409].includes(response.status))).toBe(true);
    expect(await bindings.DB.prepare("SELECT 1 FROM connections").first()).toBeNull();
    expect((await statistics()).revokeCalls).toBe(0);
    expect(
      (await api(`/v1/connections/${connection.id}`, { method: "DELETE" }, owner.credential))
        .status,
    ).toBe(404);
  });

  it("rejects tenant calendar substitution and invalid cursors before provider calls", async () => {
    await configure({
      calendarEnabled: true,
      calendarPages: [
        {
          items: [
            {
              id: "security-private-calendar",
              summary: "Security calendar",
              accessRole: "owner",
              primary: true,
            },
          ],
        },
      ],
      eventPages: [
        {
          calendarId: "security-private-calendar",
          nextPageToken: "security-next-page",
          items: [],
        },
        { calendarId: "security-private-calendar", items: [] },
      ],
    });
    const owner = await signIn("calendar-security-owner");
    const connection = await connect(owner.credential);
    const discovery = await api("/v1/calendars", {}, owner.credential);
    expect(discovery.status).toBe(200);
    const calendarId = (await discovery.json<{ calendars: { id: string }[] }>()).calendars[0]?.id;
    if (calendarId === undefined) throw new Error("expected discovered calendar");

    const other = await signIn("calendar-security-other");
    const range = "start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z";
    const beforeSubstitution = (await statistics()).eventCalls;
    expect(
      (await api(`/v1/calendars/${calendarId}/events?${range}`, {}, other.credential)).status,
    ).toBe(404);
    expect((await statistics()).eventCalls).toBe(beforeSubstitution);

    const first = await api(`/v1/calendars/${calendarId}/events?${range}`, {}, owner.credential);
    expect(first.status).toBe(200);
    const cursor = (await first.json<{ next_cursor: string }>()).next_cursor;
    const callsAfterFirst = (await statistics()).eventCalls;
    const tampered = `${cursor.slice(0, -1)}${cursor.endsWith("A") ? "B" : "A"}`;
    expect(
      (
        await api(
          `/v1/calendars/${calendarId}/events?${range}&cursor=${encodeURIComponent(tampered)}`,
          {},
          owner.credential,
        )
      ).status,
    ).toBe(400);
    expect((await statistics()).eventCalls).toBe(callsAfterFirst);

    expect(
      (await api(`/v1/connections/${connection.id}`, { method: "DELETE" }, owner.credential))
        .status,
    ).toBe(204);
    expect(
      (
        await api(
          `/v1/calendars/${calendarId}/events?${range}&cursor=${encodeURIComponent(cursor)}`,
          {},
          owner.credential,
        )
      ).status,
    ).toBe(404);
    expect((await statistics()).eventCalls).toBe(callsAfterFirst);
  });

  it("contains cross-tenant locators and stale consent callbacks after disconnect", async () => {
    const owner = await signIn("authority-owner");
    const connected = await connect(owner.credential);
    const pending = await start("/v1/connections/google/start", owner.credential);
    const staleCallback = await authorize(pending);

    const other = await signIn("other-principal");
    expect(
      (
        await post(
          `/v1/connections/google/${pending.transaction_id}/status`,
          { polling_secret: pending.polling_secret },
          other.credential,
        )
      ).status,
    ).toBe(404);
    expect(
      (await api(`/v1/connections/${connected.id}`, { method: "DELETE" }, other.credential)).status,
    ).toBe(404);
    expect(
      (await api(`/v1/devices/${owner.sessionId}`, { method: "DELETE" }, other.credential)).status,
    ).toBe(404);

    expect(
      (await api(`/v1/connections/${connected.id}`, { method: "DELETE" }, owner.credential)).status,
    ).toBe(204);
    await configure({ subject: "authority-owner", email: "same-security@example.test" });
    expect((await exports.default.fetch(new Request(staleCallback))).status).toBe(200);
    expect(await bindings.DB.prepare("SELECT 1 FROM connections").first()).toBeNull();
    expect(await statistics()).toMatchObject({ tokenRequests: 4, revokeCalls: 2 });
  });
});
