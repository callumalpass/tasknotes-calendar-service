/* eslint-disable @typescript-eslint/no-non-null-assertion, @typescript-eslint/require-await */
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  LiveGoogleCalendar,
  LiveGoogleCalendarError,
  type LiveGoogleCalendarDependencies,
} from "../../src/calendar/live-google-calendar";
import {
  GoogleAccessTokenError,
  GoogleAccessTokens,
} from "../../src/connections/google-access-tokens";
import { sealEventCursor, type EventCursorBinding } from "../../src/crypto/cursor";
import { openSyncCursor, sealSyncCursor } from "../../src/crypto/cursor";
import { sealEventId } from "../../src/crypto/event-id";
import {
  ChangesResponseSchema,
  CreateEventRequestSchema,
  PatchEventRequestSchema,
} from "../../src/contracts";
import type { FakeGoogleConfiguration, FakeGoogleStats } from "../support/fake-google";
import { encryptTokenEnvelope, type TokenPayload } from "../../src/crypto/token-envelope";
import { CalendarsResponseSchema, MAX_CALENDARS, type EventsQuery } from "../../src/contracts";
import type { Env } from "../../src/env";
import { googleTestConfiguration } from "../../src/provider/google";
import { tokenEnvelopeToRow } from "../../src/storage/token-envelope-row";

const testEnv = env as unknown as Env;
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const OTHER_PRINCIPAL = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const IDENTITY = "22222222-2222-4222-8222-222222222222";
const CONNECTION = "33333333-3333-4333-8333-333333333333";
const CALENDAR = "44444444-4444-4444-8444-444444444444";
const OTHER_CALENDAR = "55555555-5555-4555-8555-555555555555";
const CURSOR_KEY = new Uint8Array(32).fill(5);
const EVENT_KEY = new Uint8Array(32).fill(6);
const TOKEN_KEYS = { activeVersion: 1, keys: new Map([[1, new Uint8Array(32).fill(2)]]) };
const SCOPES = [
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/calendar.events",
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
] as const;
const RANGE: EventsQuery = {
  start: "2026-01-01T00:00:00Z",
  end: "2026-02-01T00:00:00Z",
};
const google = googleTestConfiguration({
  tokenEndpoint: "https://provider.test/token",
  revocationEndpoint: "https://provider.test/revoke",
  calendarApiOrigin: "https://provider.test",
});

function clockDatabase(seconds: number): D1Database {
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare")
        return (sql: string) =>
          target.prepare(sql.replaceAll("unixepoch()", `(unixepoch() + ${seconds})`));
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function randomSource() {
  let next = 0;
  return {
    bytes(length: number): Uint8Array {
      next = (next + 1) & 255;
      return new Uint8Array(length).fill(next);
    },
  };
}

function uuidSource() {
  let next = 0;
  return () => `70000000-0000-4000-8000-${String(++next).padStart(12, "0")}`;
}

async function databaseNow(): Promise<number> {
  const value = await testEnv.DB.prepare("SELECT unixepoch() AS now").first<number>("now");
  if (value === null) throw new Error("D1 clock unavailable");
  return value;
}

async function insertPrincipal(principalId = PRINCIPAL, identityId = IDENTITY): Promise<void> {
  const current = await databaseNow();
  await testEnv.DB.prepare(
    "INSERT INTO principals (id, created_at, last_active_at) VALUES (?, ?, ?)",
  )
    .bind(principalId, current, current)
    .run();
  await testEnv.DB.prepare(
    `INSERT INTO external_identities
       (id, principal_id, provider, issuer, subject, email, display_name, email_verified,
        created_at, updated_at)
     VALUES (?, ?, 'google', 'https://accounts.google.com', ?, NULL, NULL, 1, ?, ?)`,
  )
    .bind(identityId, principalId, `subject-${principalId}`, current, current)
    .run();
}

async function insertConnection(
  options: {
    principalId?: string;
    identityId?: string;
    connectionId?: string;
    generation?: number;
    tokenVersion?: number;
    expiresAt?: number;
    authorityTimestamp?: number;
  } = {},
): Promise<void> {
  const principalId = options.principalId ?? PRINCIPAL;
  const identityId = options.identityId ?? IDENTITY;
  const connectionId = options.connectionId ?? CONNECTION;
  const generation = options.generation ?? 1;
  const tokenVersion = options.tokenVersion ?? 1;
  const current = await databaseNow();
  const authorityTimestamp = options.authorityTimestamp ?? current;
  const payload: TokenPayload = {
    accessToken: `access-canary-${generation}-${tokenVersion}`,
    refreshToken: `refresh-canary-${generation}-${tokenVersion}`,
    expiresAtEpochSeconds: options.expiresAt ?? current + 3_600,
    scopes: SCOPES,
  };
  const encrypted = await encryptTokenEnvelope(
    payload,
    {
      environment: "local",
      provider: "google",
      principalId,
      connectionId,
      connectionGeneration: generation,
      tokenVersion,
      tokenKind: "calendar_oauth",
    },
    TOKEN_KEYS,
    randomSource(),
  );
  const row = tokenEnvelopeToRow(encrypted);
  await testEnv.DB.prepare(
    `INSERT INTO connections
       (id, principal_id, identity_id, provider, status, generation,
        envelope_schema_version, key_version, dek_iv, wrapped_dek, payload_iv, ciphertext,
        token_version, created_at, updated_at, last_provider_success_at)
     VALUES (?, ?, ?, 'google', 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      connectionId,
      principalId,
      identityId,
      generation,
      row.envelope_schema_version,
      row.key_version,
      row.dek_iv,
      row.wrapped_dek,
      row.payload_iv,
      row.ciphertext,
      tokenVersion,
      current,
      authorityTimestamp,
      options.authorityTimestamp ?? null,
    )
    .run();
}

async function seed(
  options: { expiresAt?: number; calendar?: boolean; authorityTimestamp?: number } = {},
): Promise<void> {
  await insertPrincipal();
  await insertConnection({
    ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
    ...(options.authorityTimestamp === undefined
      ? {}
      : { authorityTimestamp: options.authorityTimestamp }),
  });
  if (options.calendar === true) await insertCalendar();
}

async function insertCalendar(
  calendarId = CALENDAR,
  providerId = "private-provider-calendar",
  principalId = PRINCIPAL,
  connectionId = CONNECTION,
): Promise<void> {
  const current = await databaseNow();
  await testEnv.DB.prepare(
    `INSERT INTO calendars
       (id, principal_id, connection_id, provider_calendar_id, name, description,
        time_zone, access_role, is_primary, discovered_at, updated_at)
     VALUES (?, ?, ?, ?, 'Calendar', NULL, NULL, 'reader', 1, ?, ?)`,
  )
    .bind(calendarId, principalId, connectionId, providerId, current, current)
    .run();
}

interface ProviderState {
  calendarCalls: number;
  eventCalls: number;
  refreshCalls: number;
  calendarResponses: Response[];
  eventResponses: Response[];
  refreshResponse?: Response;
  blockCalendar?: Promise<void>;
  blockEvents?: Promise<void>;
}

function json(value: unknown, status = 200, headers?: HeadersInit): Response {
  return Response.json(value, { status, ...(headers === undefined ? {} : { headers }) });
}

function provider(state: ProviderState): typeof fetch {
  return async (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.pathname === "/token") {
      state.refreshCalls += 1;
      return (
        state.refreshResponse ??
        json({
          access_token: "refreshed-access",
          refresh_token: "rotated-refresh",
          expires_in: 3600,
          token_type: "Bearer",
          scope: SCOPES.join(" "),
        })
      ).clone();
    }
    if (url.pathname === "/calendar/v3/users/me/calendarList") {
      state.calendarCalls += 1;
      if (state.blockCalendar !== undefined) await state.blockCalendar;
      return (state.calendarResponses.shift() ?? json({ items: [] })).clone();
    }
    if (url.pathname.includes("/events")) {
      state.eventCalls += 1;
      if (state.blockEvents !== undefined) await state.blockEvents;
      return (state.eventResponses.shift() ?? json({ items: [] })).clone();
    }
    throw new TypeError("unexpected provider request");
  };
}

function accessTokens(
  db: D1Database,
  fetcher: typeof fetch,
  sleep = realSleep,
): GoogleAccessTokens {
  return new GoogleAccessTokens({
    db,
    environment: "local",
    googleClientId: "client",
    googleClientSecret: "secret",
    tokenKeyring: TOKEN_KEYS,
    googleProvider: google,
    fetch: fetcher,
    random: randomSource(),
    sleep,
    providerTimeoutMs: 8_000,
  });
}

function realSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function service(
  state: ProviderState,
  overrides: Partial<LiveGoogleCalendarDependencies> = {},
): LiveGoogleCalendar {
  const db = overrides.db ?? testEnv.DB;
  const fetcher = overrides.fetch ?? provider(state);
  const sleep = overrides.sleep ?? realSleep;
  return new LiveGoogleCalendar({
    db,
    accessTokens: overrides.accessTokens ?? accessTokens(db, fetcher, sleep),
    environment: "local",
    googleProvider: google,
    fetch: fetcher,
    cursorKey: overrides.cursorKey ?? CURSOR_KEY,
    eventIdKey: overrides.eventIdKey ?? EVENT_KEY,
    nowEpochSeconds: overrides.nowEpochSeconds ?? (() => 1_800_000_000),
    random: overrides.random ?? randomSource(),
    uuid: overrides.uuid ?? uuidSource(),
    sleep,
    ...(overrides.providerTimeoutMs === 0
      ? {}
      : { providerTimeoutMs: overrides.providerTimeoutMs ?? 8_000 }),
  });
}

function state(overrides: Partial<ProviderState> = {}): ProviderState {
  return {
    calendarCalls: 0,
    eventCalls: 0,
    refreshCalls: 0,
    calendarResponses: [],
    eventResponses: [],
    ...overrides,
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "LiveGoogleCalendarError",
    code,
    message: "Live calendar operation failed.",
  });
}

function acquireFaultDatabase(
  mode: "before" | "after" | "expired-after" | "delete-after",
): D1Database {
  let faulted = false;
  let expiredReadback = false;
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
        if (property === "first") {
          return async () => {
            if (faulted) return target.first();
            faulted = true;
            if (mode === "before") throw new Error("before apply");
            await target.first();
            if (mode === "expired-after") expiredReadback = true;
            if (mode === "delete-after") {
              await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?")
                .bind(CONNECTION)
                .run();
            }
            throw new Error("after apply");
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  const expired = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") return (...values: unknown[]) => expired(target.bind(...values));
        if (property === "first") {
          return async () => {
            const row = await target.first();
            return row === null || !expiredReadback
              ? row
              : { ...row, discovery_lease_until: row["server_now"] };
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (query: string) => {
          const prepared = target.prepare(query);
          if (query.includes("UPDATE connections SET discovery_lease_owner = ?"))
            return wrap(prepared);
          return mode === "expired-after" && query.includes("unixepoch() AS server_now")
            ? expired(prepared)
            : prepared;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function batchFaultDatabase(mode: "before" | "after"): D1Database {
  let faulted = false;
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          if (faulted) return target.batch(statements);
          faulted = true;
          if (mode === "before") throw new Error("before batch apply");
          await target.batch(statements);
          throw new Error("after batch apply");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function rowFaultDatabase(
  mutate: (row: Record<string, unknown>) => Record<string, unknown>,
): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
        if (property === "first") {
          return async () => {
            const row = await target.first();
            return row === null ? null : mutate(row);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (query: string) =>
          query.includes("connection.discovery_version")
            ? wrap(target.prepare(query))
            : target.prepare(query);
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function tokenRowFaultDatabase(
  mutate: (row: Record<string, unknown>) => Record<string, unknown>,
): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
        if (property === "first") {
          return async () => {
            const row = await target.first();
            return row === null ? null : mutate(row);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (query: string) =>
          query.includes("connection.envelope_schema_version")
            ? wrap(target.prepare(query))
            : target.prepare(query);
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function calendarReadFaultDatabase(
  beforeRead?: () => Promise<void>,
  corruption: Record<string, number> = {},
): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property): unknown {
        if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
        if (property === "all") {
          return async () => {
            await beforeRead?.();
            const result = await target.all();
            if (beforeRead !== undefined) return result;
            return {
              ...result,
              results: result.results.map((row) => ({ ...row, ...corruption })),
            };
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
  return new Proxy(testEnv.DB, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (query: string) =>
          query.includes("ORDER BY calendar.is_primary")
            ? wrap(target.prepare(query))
            : target.prepare(query);
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
}

function binding(overrides: Partial<EventCursorBinding> = {}): EventCursorBinding {
  return {
    principalId: PRINCIPAL,
    connectionId: CONNECTION,
    connectionGeneration: 1,
    calendarId: CALENDAR,
    rangeStart: RANGE.start,
    rangeEnd: RANGE.end,
    ...overrides,
  };
}

beforeEach(async () => {
  vi.restoreAllMocks();
  await testEnv.DB.prepare("DELETE FROM principals").run();
});

describe("stateless writes and incremental reads with fake Google and real D1", () => {
  const fake = (env as unknown as { FAKE_GOOGLE: Fetcher }).FAKE_GOOGLE;
  const binding = {
    environment: "local",
    provider: "google",
    authorizationScopedCalendarId: CALENDAR,
  } as const;
  const create = {
    idempotency_key: "88888888-8888-4888-8888-888888888888",
    title: "Private write canary",
    description: "Private description canary",
    start: { kind: "date_time", date_time: "2026-11-06T09:00:00Z", time_zone: "America/New_York" },
    end: { kind: "date_time", date_time: "2026-11-06T10:00:00Z" },
  } as const;
  const providerEvent = {
    id: "provider-event-canary",
    etag: '"1"',
    status: "confirmed" as const,
    updated: "2026-11-06T00:00:00Z",
    start: { dateTime: "2026-11-06T09:00:00Z", timeZone: "America/New_York" },
    end: { dateTime: "2026-11-06T10:00:00Z" },
  };
  const fetcher: typeof fetch = async (input, init) => {
    const request = new Request(input, { ...init, redirect: "manual" });
    request.headers.set("authorization", "Bearer fake-access");
    const url = new URL(request.url);
    return fake.fetch(new Request(`http://127.0.0.1:9797${url.pathname}${url.search}`, request));
  };
  async function configure(value: FakeGoogleConfiguration): Promise<void> {
    const response = await fake.fetch("https://fake-google-control.test/configure", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    });
    expect(response.status).toBe(204);
  }
  async function stats(): Promise<FakeGoogleStats> {
    return (await fake.fetch("https://fake-google-control.test/stats")).json();
  }
  async function setup(writable = true) {
    await fake.fetch("https://fake-google-control.test/reset", { method: "POST" });
    await seed({ calendar: true });
    if (writable) await testEnv.DB.prepare("UPDATE calendars SET access_role = 'writer'").run();
    await configure({
      calendarEnabled: true,
      eventPages: [{ calendarId: "private-provider-calendar", items: [providerEvent] }],
    });
    return service(state(), { fetch: fetcher });
  }

  it("creates idempotently, reads, patches conditionally, and deletes an already gone event", async () => {
    const instance = await setup();
    const first = await instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create);
    const replay = await instance.event(PRINCIPAL, CALENDAR, "POST", undefined, {
      ...create,
      title: "Must not replace original",
    });
    expect(replay).toEqual(first);
    expect(first!.id).toMatch(/^e1_/u);
    expect(first).toMatchObject({
      title: create.title,
      etag: '"1"',
    });
    expect(await instance.event(PRINCIPAL, CALENDAR, "GET", first!.id)).toEqual(first);
    const patched = await instance.event(
      PRINCIPAL,
      CALENDAR,
      "PATCH",
      first!.id,
      { title: "Changed" },
      first!.etag!,
    );
    expect(patched).toMatchObject({ title: "Changed", etag: '"2"' });
    await expectCode(
      instance.event(PRINCIPAL, CALENDAR, "PATCH", first!.id, { title: "Stale" }, first!.etag!),
      "conflict",
    );
    await instance.event(PRINCIPAL, CALENDAR, "DELETE", first!.id, undefined, patched!.etag!);
    await expect(
      instance.event(PRINCIPAL, CALENDAR, "DELETE", first!.id, undefined, patched!.etag!),
    ).resolves.toBeUndefined();
    await expectCode(instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create), "conflict");
    const persisted = JSON.stringify(await testEnv.DB.prepare("SELECT * FROM calendars").all());
    expect(persisted).not.toContain(create.title);
    expect(persisted).not.toContain("provider-event-canary");
  });

  it("switches boundary kinds on PATCH without leaving the previous kind's fields", async () => {
    const instance = await setup();
    const timed = await instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create);
    const allDay = await instance.event(
      PRINCIPAL,
      CALENDAR,
      "PATCH",
      timed!.id,
      {
        start: { kind: "date", date: "2026-11-06" },
        end: { kind: "date", date: "2026-11-07" },
      },
      timed!.etag!,
    );
    expect(allDay!.start).toEqual({ kind: "date", date: "2026-11-06" });
    const timedAgain = await instance.event(
      PRINCIPAL,
      CALENDAR,
      "PATCH",
      allDay!.id,
      { start: create.start, end: create.end },
      allDay!.etag!,
    );
    expect(timedAgain!.start).toEqual(create.start);
  });

  it("reports a provider 400 on a write as invalid input without failing reads the same way", async () => {
    await seed({ calendar: true });
    await testEnv.DB.prepare("UPDATE calendars SET access_role = 'writer'").run();
    await expectCode(
      service(state({ eventResponses: [json({ error: { code: 400 } }, 400)] })).event(
        PRINCIPAL,
        CALENDAR,
        "POST",
        undefined,
        create,
      ),
      "invalid_request",
    );
    await expectCode(
      service(state({ eventResponses: [json({ error: { code: 400 } }, 400)] })).listChanges(
        PRINCIPAL,
        CALENDAR,
        {},
      ),
      "unavailable",
    );
  });

  it("treats an id-only deleted event from GET as gone", async () => {
    await seed({ calendar: true });
    await testEnv.DB.prepare("UPDATE calendars SET access_role = 'writer'").run();
    const id = await sealEventId(providerEvent.id, binding, EVENT_KEY);
    await expectCode(
      service(state({ eventResponses: [json({ id: providerEvent.id })] })).event(
        PRINCIPAL,
        CALENDAR,
        "GET",
        id,
      ),
      "not_found",
    );
    await expectCode(
      service(
        state({
          eventResponses: [json({ error: { code: 409 } }, 409), json({ id: providerEvent.id })],
        }),
      ).event(PRINCIPAL, CALENDAR, "POST", undefined, create),
      "conflict",
    );
  });

  it("refreshes again when Google rejects a token that was just refreshed", async () => {
    await seed({ calendar: true, expiresAt: (await databaseNow()) - 10 });
    const provided = state({
      eventResponses: [json({ error: { code: 401 } }, 401), json(providerEvent)],
    });
    const id = await sealEventId(providerEvent.id, binding, EVENT_KEY);
    await expect(service(provided).event(PRINCIPAL, CALENDAR, "GET", id)).resolves.toMatchObject({
      id,
    });
    expect(provided.refreshCalls).toBe(2);
    expect(provided.eventCalls).toBe(2);
  });

  it("does not let a token refresh renew calendar discovery freshness", async () => {
    await seed();
    const item = { id: "discovered-calendar", summary: "Calendar", accessRole: "owner" };
    const provided = state({
      calendarResponses: [json({ items: [item] }), json({ items: [item] })],
    });
    await service(provided).listCalendars(PRINCIPAL);
    const later = (await databaseNow()) + 3_600;
    await testEnv.DB.prepare(
      "UPDATE connections SET updated_at = ?1, last_provider_success_at = ?1",
    )
      .bind(later)
      .run();
    await service(provided, { db: clockDatabase(later) }).listCalendars(PRINCIPAL);
    expect(provided.calendarCalls).toBe(2);
  });

  it("keeps cached calendars when a benign refresh lands during the read", async () => {
    await seed();
    const provided = state({
      calendarResponses: [
        json({ items: [{ id: "discovered-calendar", summary: "Calendar", accessRole: "owner" }] }),
      ],
    });
    const instance = service(provided);
    await instance.listCalendars(PRINCIPAL);
    const tokens = accessTokens(testEnv.DB, provider(provided));
    const db = calendarReadFaultDatabase(async () => {
      await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!, { forceRefresh: true });
    });
    const { calendars } = await service(provided, { db }).listCalendars(PRINCIPAL);
    expect(calendars).toHaveLength(1);
    expect(provided.calendarCalls).toBe(1);
  });

  it("rejects tenant and calendar substitution without token or provider calls", async () => {
    const instance = await setup();
    const id = await sealEventId(providerEvent.id, binding, EVENT_KEY);
    await expectCode(instance.event(OTHER_PRINCIPAL, CALENDAR, "GET", id), "not_found");
    await insertCalendar(OTHER_CALENDAR, "second-calendar");
    await expectCode(instance.event(PRINCIPAL, OTHER_CALENDAR, "GET", id), "not_found");
    const other = await sealEventId(
      providerEvent.id,
      { ...binding, authorizationScopedCalendarId: OTHER_CALENDAR },
      EVENT_KEY,
    );
    await expectCode(
      instance.event(PRINCIPAL, CALENDAR, "PATCH", other, { title: "Denied" }, '"1"'),
      "not_found",
    );
    expect((await stats()).calendarCalls).toBe(0);
    expect((await stats()).refreshRequests).toBe(0);
  });

  it("rejects a read-only calendar before token work", async () => {
    const instance = await setup(false);
    await expectCode(
      instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create),
      "permission_denied",
    );
    expect((await stats()).calendarCalls).toBe(0);
    expect((await stats()).refreshRequests).toBe(0);
  });

  it("disconnect before a write reaches Google prevents that call", async () => {
    await setup();
    const tokens = accessTokens(testEnv.DB, fetcher);
    const original = tokens.assertCurrent.bind(tokens);
    vi.spyOn(tokens, "assertCurrent").mockImplementationOnce(async (grant) => {
      await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
      return original(grant);
    });
    const instance = service(state(), { fetch: fetcher, accessTokens: tokens });
    await expectCode(instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create), "not_found");
    expect((await stats()).calendarCalls).toBe(0);
  });

  it("does not repeat timed-out writes", async () => {
    await setup();
    await configure({ calendar: "stall" });
    const timed = service(state(), { fetch: fetcher, providerTimeoutMs: 20 });
    await expectCode(timed.event(PRINCIPAL, CALENDAR, "POST", undefined, create), "unavailable");
    expect((await stats()).eventCalls).toBe(1);
  });

  it.each(["range", "changes", "one"] as const)(
    "discards %s results revoked while preparing the response",
    async (operation) => {
      await setup();
      const tokens = accessTokens(testEnv.DB, fetcher);
      const original = tokens.assertCurrent.bind(tokens);
      let checks = 0;
      vi.spyOn(tokens, "assertCurrent").mockImplementation(async (grant) => {
        await original(grant);
        checks += 1;
        if (checks === 2)
          await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
      });
      const instance = service(state(), { fetch: fetcher, accessTokens: tokens });
      const eventId = await sealEventId(providerEvent.id, binding, EVENT_KEY);
      const result =
        operation === "range"
          ? instance.listEvents(PRINCIPAL, CALENDAR, RANGE)
          : operation === "changes"
            ? instance.listChanges(PRINCIPAL, CALENDAR, {})
            : instance.event(PRINCIPAL, CALENDAR, "GET", eventId);
      await expectCode(result, "not_found");
      expect((await stats()).eventCalls).toBe(1);
    },
  );

  it("refreshes once on an unapplied 401 and repeats no other provider failure", async () => {
    await setup();
    let refreshes = 0;
    const refreshingFetch: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/token") {
        refreshes += 1;
        return json({
          access_token: "fake-access",
          expires_in: 3600,
          token_type: "Bearer",
          scope: SCOPES.join(" "),
        });
      }
      return fetcher(input, init);
    };
    const instance = service(state(), { fetch: refreshingFetch });
    await configure({ calendar: "unauthorized" });
    const event = await instance.event(PRINCIPAL, CALENDAR, "POST", undefined, create);
    expect(event?.title).toBe(create.title);
    expect(refreshes).toBe(1);
    expect((await stats()).eventCalls).toBe(2);
    await configure({ calendar: "server_error" });
    await expectCode(
      instance.event(PRINCIPAL, CALENDAR, "DELETE", event!.id, undefined, event!.etag!),
      "unavailable",
    );
    expect((await stats()).eventCalls).toBe(3);
    expect(refreshes).toBe(1);
  });

  it("rejects invalid merged intervals and recurrence changes to an instance before mutation", async () => {
    const instance = await setup();
    const id = await sealEventId(providerEvent.id, binding, EVENT_KEY);
    await expectCode(
      instance.event(
        PRINCIPAL,
        CALENDAR,
        "PATCH",
        id,
        { end: { kind: "date_time", date_time: "2020-01-01T00:00:00Z" } },
        '"1"',
      ),
      "invalid_request",
    );
    expect((await stats()).eventCalls).toBe(1);
    await configure({
      eventPages: [
        {
          calendarId: "private-provider-calendar",
          items: [
            {
              ...providerEvent,
              recurringEventId: "series",
              originalStartTime: providerEvent.start,
            },
          ],
        },
      ],
    });
    await expectCode(
      instance.event(PRINCIPAL, CALENDAR, "PATCH", id, { recurrence: ["RRULE:FREQ=DAILY"] }, '"1"'),
      "invalid_request",
    );
    expect((await stats()).eventCalls).toBe(2);
    expect((await instance.event(PRINCIPAL, CALENDAR, "GET", id))?.etag).toBe('"1"');
  });

  it("returns cross-zone and zero-duration events and counts malformed events", async () => {
    const instance = await setup();
    await configure({
      eventPages: [
        {
          calendarId: "private-provider-calendar",
          items: [
            providerEvent,
            { ...providerEvent, id: "zero", end: providerEvent.start },
            {
              ...providerEvent,
              id: "unknown-zone",
              start: { ...providerEvent.start, timeZone: "Unknown/Zone" },
            },
            { ...providerEvent, id: "invalid", end: { dateTime: "2020-01-01T00:00:00Z" } },
            { ...providerEvent, id: "x".repeat(1025) },
          ],
        },
      ],
    });
    const result = await instance.listEvents(PRINCIPAL, CALENDAR, {
      start: "2026-11-01T00:00:00Z",
      end: "2026-12-01T00:00:00Z",
    });
    expect(result.omitted_count).toBe(2);
    expect(result.events).toHaveLength(3);
    expect(result.events[0]?.start).toMatchObject({ time_zone: "America/New_York" });
    expect(result.events[1]?.start).toEqual(result.events[1]?.end);
    expect(result.events[2]?.start).not.toHaveProperty("time_zone");
  });

  it("accepts a complete page of 250 long events over the former one-MiB limit", async () => {
    const instance = await setup();
    await configure({
      eventPages: [
        {
          calendarId: "private-provider-calendar",
          items: Array.from({ length: 250 }, (_, index) => ({
            ...providerEvent,
            id: `event-${index}`,
            description: "x".repeat(14000),
          })),
        },
      ],
    });
    const result = await instance.listEvents(PRINCIPAL, CALENDAR, RANGE);
    expect(result.events).toHaveLength(250);
    expect(result.omitted_count).toBe(0);
  });

  it("pages an initial full sync without filters and returns an id-only tombstone", async () => {
    const instance = await setup();
    await configure({
      eventPages: [
        {
          calendarId: "private-provider-calendar",
          items: [providerEvent],
          nextPageToken: "page-two",
        },
        { calendarId: "private-provider-calendar", items: [{ id: "gone" }] },
      ],
    });
    const first = await instance.listChanges(PRINCIPAL, CALENDAR, {});
    expect(first.next_cursor).not.toBeNull();
    expect(first.sync_cursor).toBeNull();
    const final = await instance.listChanges(PRINCIPAL, CALENDAR, { cursor: first.next_cursor! });
    expect(ChangesResponseSchema.safeParse(final).success).toBe(true);
    expect(final.events[0]).toMatchObject({
      status: "cancelled",
      start: null,
      end: null,
      updated_at: null,
      etag: null,
    });
    expect(final.omitted_count).toBe(0);
    expect(final.next_cursor).toBeNull();
    const anotherWorker = service(state(), {
      fetch: fetcher,
      nowEpochSeconds: () => 9_000_000_000,
    });
    const incremental = await anotherWorker.listChanges(PRINCIPAL, CALENDAR, {
      cursor: final.sync_cursor!,
    });
    expect(incremental.next_cursor).not.toBeNull();
    const continued = await openSyncCursor(
      incremental.next_cursor!,
      {
        principalId: PRINCIPAL,
        connectionId: CONNECTION,
        connectionGeneration: 1,
        calendarId: CALENDAR,
      },
      CURSOR_KEY,
    );
    expect(continued).toEqual({ syncToken: "fake-sync-current", pageToken: "page-two" });
    expect((await stats()).eventCalls).toBe(3);
  });

  it("maps an expired Google sync token to sync_reset_required", async () => {
    const instance = await setup();
    const cursor = await sealSyncCursor(
      { syncToken: "expired" },
      {
        principalId: PRINCIPAL,
        connectionId: CONNECTION,
        connectionGeneration: 1,
        calendarId: CALENDAR,
      },
      CURSOR_KEY,
    );
    await expectCode(instance.listChanges(PRINCIPAL, CALENDAR, { cursor }), "sync_reset_required");
    expect((await stats()).eventCalls).toBe(1);
  });

  it("keeps page and sync cursors purpose-separated and binds sync authority", async () => {
    const instance = await setup();
    const cursor = await sealEventCursor(
      "private",
      {
        principalId: PRINCIPAL,
        connectionId: CONNECTION,
        connectionGeneration: 1,
        calendarId: CALENDAR,
        rangeStart: RANGE.start,
        rangeEnd: RANGE.end,
      },
      1800000000,
      CURSOR_KEY,
    );
    await expectCode(instance.listChanges(PRINCIPAL, CALENDAR, { cursor }), "invalid_request");
    const first = await instance.listChanges(PRINCIPAL, CALENDAR, {});
    await expectCode(
      instance.listEvents(PRINCIPAL, CALENDAR, { ...RANGE, cursor: first.sync_cursor! }),
      "invalid_request",
    );
    for (const wrong of [
      { principalId: OTHER_PRINCIPAL },
      { connectionGeneration: 2 },
      { calendarId: OTHER_CALENDAR },
    ]) {
      await expect(
        openSyncCursor(
          first.sync_cursor!,
          {
            principalId: PRINCIPAL,
            connectionId: CONNECTION,
            connectionGeneration: 1,
            calendarId: CALENDAR,
            ...wrong,
          },
          CURSOR_KEY,
        ),
      ).rejects.toThrow();
    }
    expect((await stats()).eventCalls).toBe(1);
  });

  it("bounds write schemas without adding plugin-only reminder or color fields", () => {
    expect(CreateEventRequestSchema.safeParse(create).success).toBe(true);
    expect(
      CreateEventRequestSchema.safeParse({ ...create, reminders: { useDefault: true } }).success,
    ).toBe(false);
    expect(CreateEventRequestSchema.safeParse({ ...create, colorId: "1" }).success).toBe(false);
    expect(PatchEventRequestSchema.safeParse({}).success).toBe(false);
    expect(
      PatchEventRequestSchema.safeParse({ recurrence: ["RRULE:FREQ=DAILY\nATTENDEE:unsafe"] })
        .success,
    ).toBe(false);
    expect(
      PatchEventRequestSchema.safeParse({
        recurrence: ["RRULE:FREQ=DAILY", "EXDATE:20261106T090000Z", "RDATE:20261107T090000Z"],
      }).success,
    ).toBe(true);
    expect(
      CreateEventRequestSchema.safeParse({ ...create, end: { kind: "date", date: "2026-11-07" } })
        .success,
    ).toBe(false);
  });
});

describe("LiveGoogleCalendar with real D1", () => {
  it("uses D1 discovery freshness without token work, provider calls, or D1 writes", async () => {
    await seed();
    const providerState = state({
      calendarResponses: [
        json({ items: [{ id: "calendar", summary: "Calendar", accessRole: "writer" }] }),
      ],
    });
    const first = await service(providerState).listCalendars(PRINCIPAL);
    const before = await testEnv.DB.prepare("SELECT * FROM connections").first();
    const tokens = accessTokens(testEnv.DB, provider(providerState));
    const access = vi.spyOn(tokens, "access");
    const load = vi.spyOn(tokens, "loadForPrincipal");
    const second = await service(providerState, {
      accessTokens: tokens,
      nowEpochSeconds: () => 1,
    }).listCalendars(PRINCIPAL);
    // Only the request that asked the provider reports on the provider's list.
    expect(first.discovery).toEqual({ omittedCount: 0, truncated: false });
    expect(second).toEqual({ calendars: first.calendars });
    expect(second.calendars[0]?.can_write).toBe(true);
    expect(providerState.calendarCalls).toBe(1);
    expect(access).not.toHaveBeenCalled();
    expect(load).not.toHaveBeenCalled();
    expect(await testEnv.DB.prepare("SELECT * FROM connections").first()).toEqual(before);
  });
  it("serializes 20 service instances, keeps stable IDs, uses D1 time, and authoritatively deletes", async () => {
    await seed();
    const firstPage = {
      items: [
        {
          id: "private-a",
          summary: "Primary",
          description: "description",
          timeZone: "Europe/London",
          accessRole: "owner",
          primary: true,
          selected: true,
        },
        { id: "private-b", summary: "Secondary", accessRole: "reader" },
      ],
    };
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => (release = resolve));
    const providerState = state({
      calendarResponses: [json(firstPage)],
      blockCalendar: blocked,
    });
    const services = Array.from({ length: 20 }, () => service(providerState));
    const reads = [
      services[0]!.listCalendars(PRINCIPAL),
      services[0]!.listCalendars(PRINCIPAL),
      ...services.slice(1).map((instance) => instance.listCalendars(PRINCIPAL)),
    ];
    await vi.waitFor(() => expect(providerState.calendarCalls).toBe(1));
    release();
    const results = await Promise.all(reads);
    expect(providerState.calendarCalls).toBe(1);
    expect(new Set(results.map((value) => value.calendars[0]?.id))).toHaveLength(1);
    expect(results[0]?.calendars.map((calendar) => calendar.name)).toEqual([
      "Primary",
      "Secondary",
    ]);
    const persisted = await testEnv.DB.prepare(
      "SELECT id, provider_calendar_id, discovered_at, updated_at FROM calendars ORDER BY provider_calendar_id",
    ).all<{
      id: string;
      provider_calendar_id: string;
      discovered_at: number;
      updated_at: number;
    }>();
    const d1Now = await databaseNow();
    expect(persisted.results.every((row) => Math.abs(row.discovered_at - d1Now) <= 1)).toBe(true);
    expect(persisted.results.every((row) => row.updated_at === row.discovered_at)).toBe(true);

    delete providerState.blockCalendar;
    providerState.calendarResponses.push(json({ items: [] }));
    const skewed = service(providerState, { db: clockDatabase(301), nowEpochSeconds: () => 1 });
    await expect(skewed.listCalendars(PRINCIPAL)).resolves.toEqual({
      calendars: [],
      discovery: { omittedCount: 0, truncated: false },
    });
    expect(await testEnv.DB.prepare("SELECT 1 FROM calendars").first()).toBeNull();
  });

  it("accepts 250 terminal calendars and rejects a duplicate page without mutation", async () => {
    await seed();
    const items = Array.from({ length: 250 }, (_, index) => ({
      id: `provider-${index}`,
      summary: `Calendar ${String(index).padStart(3, "0")}`,
      accessRole: "reader",
    }));
    const providerState = state({ calendarResponses: [json({ items })] });
    let instance = service(providerState);
    const terminal = await instance.listCalendars(PRINCIPAL);
    expect(terminal.calendars).toHaveLength(250);
    expect(terminal.calendars[0]?.name).toBe("Calendar 000");
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
      count: 250,
    });
    instance = service(providerState, { db: clockDatabase(301) });
    providerState.calendarResponses.push(json({ items: [items[0], items[0]] }));
    await expectCode(instance.listCalendars(PRINCIPAL), "unavailable");
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
      count: 250,
    });
    // The same calendar on two pages is as unusable as twice on one.
    providerState.calendarResponses.push(
      json({ items: [items[0]], nextPageToken: "more-calendars" }),
      json({ items: [items[0]] }),
    );
    await expectCode(instance.listCalendars(PRINCIPAL), "unavailable");
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
      count: 250,
    });
  });

  it("reads a calendar list to its end across pages and replaces mappings once", async () => {
    await seed();
    const page = (number: number, count: number, more: boolean) =>
      json({
        items: Array.from({ length: count }, (_, index) => ({
          id: `page-${number}-provider-${index}`,
          summary: `Calendar ${number}.${String(index).padStart(3, "0")}`,
          accessRole: index === 0 ? "curator" : "reader",
        })),
        ...(more ? { nextPageToken: `after-page-${number}` } : {}),
      });
    const providerState = state({
      calendarResponses: [page(1, 250, true), page(2, 250, true), page(3, 7, false)],
    });
    const listed = await service(providerState).listCalendars(PRINCIPAL);
    expect(providerState.calendarCalls).toBe(3);
    // One calendar per page has a role the service does not know.
    expect(listed.calendars).toHaveLength(504);
    expect(listed.discovery).toEqual({ omittedCount: 3, truncated: false });
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
      count: 504,
    });
    expect(
      await testEnv.DB.prepare("SELECT discovery_version FROM connections WHERE id = ?")
        .bind(CONNECTION)
        .first(),
    ).toEqual({ discovery_version: 1 });

    // A later, shorter list is authoritative: mappings it no longer names are removed.
    providerState.calendarResponses.push(page(2, 3, false));
    const again = await service(providerState, { db: clockDatabase(301) }).listCalendars(PRINCIPAL);
    expect(again.calendars.map((calendar) => calendar.name)).toEqual([
      "Calendar 2.001",
      "Calendar 2.002",
    ]);
    const kept = listed.calendars.filter((calendar) => calendar.name.startsWith("Calendar 2.00"));
    expect(again.calendars.map((calendar) => calendar.id).sort()).toEqual(
      kept
        .filter((calendar) => /\.00[12]$/u.test(calendar.name))
        .map((calendar) => calendar.id)
        .sort(),
    );
  });

  it("lists at most the response bound and reports that the provider had more", async () => {
    await seed();
    const page = (number: number) =>
      json({
        items: Array.from({ length: 250 }, (_, index) => ({
          id: `page-${number}-provider-${index}`,
          summary: `Calendar ${number}.${String(index).padStart(3, "0")}`,
          accessRole: "reader",
        })),
        nextPageToken: `after-page-${number}`,
      });
    const providerState = state({
      calendarResponses: [page(1), page(2), page(3), page(4), page(5)],
    });
    const listed = await service(providerState).listCalendars(PRINCIPAL);
    expect(providerState.calendarCalls).toBe(4);
    expect(listed.calendars).toHaveLength(MAX_CALENDARS);
    expect(listed.discovery).toEqual({ omittedCount: 0, truncated: true });
    expect(CalendarsResponseSchema.safeParse({ calendars: listed.calendars }).success).toBe(true);
  });

  it("abandons a list when a later page fails, leaving mappings as they were", async () => {
    await seed();
    const providerState = state({
      calendarResponses: [
        json({
          items: [{ id: "first-page", summary: "First", accessRole: "reader" }],
          nextPageToken: "more",
        }),
        json({ error: "server" }, 500),
      ],
    });
    await expect(service(providerState).listCalendars(PRINCIPAL)).rejects.toMatchObject({
      code: "unavailable",
      detail: "provider_unavailable",
    });
    expect(providerState.calendarCalls).toBe(2);
    expect(await testEnv.DB.prepare("SELECT 1 FROM calendars").first()).toBeNull();
    expect(
      await testEnv.DB.prepare(
        "SELECT discovery_version, discovery_lease_owner FROM connections WHERE id = ?",
      )
        .bind(CONNECTION)
        .first(),
    ).toEqual({ discovery_version: 0, discovery_lease_owner: null });
  });

  it.each([0, 250] as const)(
    "commits %i mappings when provider-success and update timestamps remain equal",
    async (count) => {
      const futureTimestamp = (await databaseNow()) + 60;
      await seed({ authorityTimestamp: futureTimestamp });
      const items = Array.from({ length: count }, (_, index) => ({
        id: `same-second-provider-${index}`,
        summary: `Same second ${index}`,
        accessRole: "reader",
      }));
      const providerState = state({ calendarResponses: [json({ items })] });

      const result = await service(providerState).listCalendars(PRINCIPAL);
      expect(result.calendars).toHaveLength(count);
      expect(providerState.calendarCalls).toBe(1);
      expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
        count,
      });
      expect(
        await testEnv.DB.prepare(
          `SELECT discovery_version, discovery_lease_owner, updated_at,
                  last_provider_success_at FROM connections WHERE id = ?`,
        )
          .bind(CONNECTION)
          .first(),
      ).toEqual({
        discovery_version: 1,
        discovery_lease_owner: null,
        updated_at: futureTimestamp,
        last_provider_success_at: futureTimestamp,
      });
    },
  );

  it.each(["before", "after", "expired-after", "delete-after"] as const)(
    "resolves ambiguous discovery acquisition %s without an unauthorized provider call",
    async (mode) => {
      await seed();
      const providerState = state({ calendarResponses: [json({ items: [] })] });
      const db = acquireFaultDatabase(mode);
      const instance = service(providerState, {
        db,
        accessTokens: accessTokens(testEnv.DB, provider(providerState), async () => undefined),
        sleep: async () => undefined,
      });
      if (mode === "expired-after" || mode === "delete-after") {
        await expectCode(
          instance.listCalendars(PRINCIPAL),
          mode === "delete-after" ? "conflict" : "unavailable",
        );
        expect(providerState.calendarCalls).toBe(0);
      } else {
        await expect(instance.listCalendars(PRINCIPAL)).resolves.toEqual({
          calendars: [],
          discovery: { omittedCount: 0, truncated: false },
        });
        expect(providerState.calendarCalls).toBe(1);
      }
    },
  );

  it.each(["before", "after"] as const)(
    "recovers an ambiguous discovery batch %s apply without repeating the provider GET",
    async (mode) => {
      await seed();
      const providerState = state({
        calendarResponses: [
          json({ items: [{ id: "provider", summary: "Calendar", accessRole: "reader" }] }),
        ],
      });
      const db = batchFaultDatabase(mode);
      const instance = service(providerState, {
        db,
        accessTokens: accessTokens(testEnv.DB, provider(providerState)),
      });
      await expect(instance.listCalendars(PRINCIPAL)).resolves.toMatchObject({
        calendars: [expect.objectContaining({ name: "Calendar" })],
      });
      expect(providerState.calendarCalls).toBe(1);
      expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM calendars").first()).toEqual({
        count: 1,
      });
    },
  );

  it("opens every cursor before expired-token access, including old-generation replacement cursors", async () => {
    const current = await databaseNow();
    await seed({ expiresAt: current - 1, calendar: true });
    const providerState = state();
    const instance = service(providerState, { nowEpochSeconds: () => 1_800_000_000 });
    const valid = await sealEventCursor(
      "page-two",
      binding(),
      1_800_000_000,
      CURSOR_KEY,
      randomSource(),
    );
    const cases: {
      cursor: string;
      principal?: string;
      calendar?: string;
      query?: EventsQuery;
    }[] = [
      { cursor: `${valid.slice(0, -1)}${valid.endsWith("A") ? "B" : "A"}` },
      {
        cursor: await sealEventCursor("page", binding(), 1_799_999_399, CURSOR_KEY, randomSource()),
      },
      {
        cursor: valid,
        query: { start: RANGE.start, end: "2026-02-02T00:00:00Z", cursor: valid },
      },
      { cursor: valid, calendar: OTHER_CALENDAR },
      { cursor: valid, principal: OTHER_PRINCIPAL },
      {
        cursor: await sealEventCursor(
          "page",
          binding({ connectionGeneration: 2 }),
          1_800_000_000,
          CURSOR_KEY,
          randomSource(),
        ),
      },
    ];
    await insertPrincipal(OTHER_PRINCIPAL, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    await insertCalendar(OTHER_CALENDAR, "other-private");
    for (const item of cases) {
      await expectCode(
        instance.listEvents(
          item.principal ?? PRINCIPAL,
          item.calendar ?? CALENDAR,
          item.query ?? { ...RANGE, cursor: item.cursor },
        ),
        item.principal === OTHER_PRINCIPAL ? "not_found" : "invalid_request",
      );
    }
    expect(providerState.refreshCalls).toBe(0);
    expect(providerState.eventCalls).toBe(0);

    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    await insertConnection({ generation: 3, tokenVersion: 1, expiresAt: current - 1 });
    await insertCalendar(CALENDAR, "new-private");
    await expectCode(
      instance.listEvents(PRINCIPAL, CALENDAR, { ...RANGE, cursor: valid }),
      "invalid_request",
    );
    expect(providerState.refreshCalls).toBe(0);
    expect(providerState.eventCalls).toBe(0);
  });

  it("does not conflict when refresh wins between a grant and discovery authority lookup", async () => {
    await seed();
    const providerState = state();
    const tokens = accessTokens(testEnv.DB, provider(providerState));
    const access = tokens.access.bind(tokens);
    vi.spyOn(tokens, "access").mockImplementation(async (...args) => {
      const grant = await access(...args);
      await access((await tokens.loadForPrincipal(PRINCIPAL))!, { forceRefresh: true });
      return grant;
    });
    await expect(
      service(providerState, { accessTokens: tokens }).listCalendars(PRINCIPAL),
    ).resolves.toHaveProperty("calendars");
    expect(providerState.refreshCalls).toBe(1);
  });

  it("releases event results after a benign refresh during the provider read", async () => {
    await seed({ calendar: true });
    const providerState = state();
    const tokens = accessTokens(testEnv.DB, provider(providerState));
    const fetcher: typeof fetch = async (input, init) => {
      const response = await provider(providerState)(input, init);
      await tokens.access((await tokens.loadForPrincipal(PRINCIPAL))!, { forceRefresh: true });
      return response;
    };
    await expect(
      service(providerState, { accessTokens: tokens, fetch: fetcher }).listEvents(
        PRINCIPAL,
        CALENDAR,
        RANGE,
      ),
    ).resolves.toHaveProperty("events");
    expect(providerState.refreshCalls).toBe(1);
  });

  it("maps live event pages, refreshes exactly once after Calendar 401, and preserves tombstones", async () => {
    await seed({ calendar: true });
    const providerState = state({
      eventResponses: [
        json({ error: "unauthorized" }, 401),
        json({
          nextPageToken: "page-two",
          items: [
            {
              id: "timed-private",
              status: "confirmed",
              etag: '"1"',
              updated: "2026-01-01T00:00:00Z",
              summary: "Timed",
              start: { dateTime: "2026-01-02T10:00:00Z" },
              end: { dateTime: "2026-01-02T11:00:00Z" },
            },
            {
              id: "all-day-private",
              status: "tentative",
              etag: '"1"',
              updated: "2026-01-01T00:00:00Z",
              start: { date: "2026-01-03" },
              end: { date: "2026-01-04" },
            },
          ],
        }),
        json({
          items: [
            {
              id: "tombstone-private",
              status: "cancelled",
              etag: '"1"',
              updated: "2026-01-01T00:00:00Z",
              recurringEventId: "series-private",
              originalStartTime: { dateTime: "2026-01-05T10:00:00Z" },
            },
          ],
        }),
      ],
    });
    const instance = service(providerState);
    const first = await instance.listEvents(PRINCIPAL, CALENDAR, RANGE);
    expect(providerState.refreshCalls).toBe(1);
    expect(providerState.eventCalls).toBe(2);
    expect(first.events).toHaveLength(2);
    expect(first.events[1]).toMatchObject({
      start: { kind: "date", date: "2026-01-03" },
      end: { kind: "date", date: "2026-01-04" },
    });
    expect(JSON.stringify(first)).not.toContain("private");
    const second = await instance.listEvents(PRINCIPAL, CALENDAR, {
      ...RANGE,
      cursor: first.next_cursor!,
    });
    expect(second.events[0]).toMatchObject({ status: "cancelled", start: null, end: null });
    expect(second.next_cursor).toBeNull();
  });

  it.each([
    [json({ error: { errors: [{ reason: "forbidden" }] } }, 403), "not_found"],
    [json({ error: "missing" }, 404), "not_found"],
    [json({ error: "rate" }, 429, { "retry-after": "99999" }), "rate"],
    [json({ error: "down" }, 503), "unavailable"],
    [new Response("{", { headers: { "content-type": "application/json" } }), "unavailable"],
    [json({ items: "bad" }), "unavailable"],
  ] as const)(
    "maps event provider failure %# without leaking provider data",
    async (response, code) => {
      await seed({ calendar: true });
      const providerState = state({ eventResponses: [response] });
      await expectCode(service(providerState).listEvents(PRINCIPAL, CALENDAR, RANGE), code);
      expect(providerState.eventCalls).toBe(1);
    },
  );

  it("discards discovery and event responses after disconnect while provider reads are blocked", async () => {
    await seed({ calendar: true });
    let releaseCalendar!: () => void;
    let releaseEvents!: () => void;
    const providerState = state({
      calendarResponses: [json({ items: [{ id: "late", summary: "Late", accessRole: "reader" }] })],
      eventResponses: [json({ items: [] })],
      blockCalendar: new Promise<void>((resolve) => (releaseCalendar = resolve)),
      blockEvents: new Promise<void>((resolve) => (releaseEvents = resolve)),
    });
    const discovery = service(providerState).listCalendars(PRINCIPAL);
    await vi.waitFor(() => expect(providerState.calendarCalls).toBe(1));
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    releaseCalendar();
    await expectCode(discovery, "conflict");
    expect(await testEnv.DB.prepare("SELECT 1 FROM calendars").first()).toBeNull();

    await insertConnection({ generation: 3 });
    await insertCalendar(CALENDAR, "private-provider-calendar");
    const events = service(providerState).listEvents(PRINCIPAL, CALENDAR, RANGE);
    await vi.waitFor(() => expect(providerState.eventCalls).toBe(1));
    await testEnv.DB.prepare("DELETE FROM connections WHERE id = ?").bind(CONNECTION).run();
    releaseEvents();
    await expectCode(events, "not_found");
  });

  it.each([
    [json({ error: { errors: [{ reason: "forbidden" }] } }, 403), "conflict"],
    [
      json({ error: { errors: [{ reason: "quotaExceeded" }] } }, 403, { "retry-after": "9" }),
      "rate",
    ],
    [json({ error: "rate" }, 429, { "retry-after": "99999" }), "rate"],
    [json({ error: "missing" }, 404), "unavailable"],
    [json({ error: "down" }, 500), "unavailable"],
    [new Response("not-json", { headers: { "content-type": "application/json" } }), "unavailable"],
    [json({ items: "not-an-array" }), "unavailable"],
  ] as const)(
    "maps discovery provider failure %# and releases its exact lease",
    async (response, code) => {
      await seed();
      const providerState = state({ calendarResponses: [response] });
      const instance = service(providerState);
      await expectCode(instance.listCalendars(PRINCIPAL), code);
      expect(providerState.calendarCalls).toBe(1);
      expect(
        await testEnv.DB.prepare("SELECT discovery_lease_owner FROM connections").first(),
      ).toEqual({ discovery_lease_owner: null });
    },
  );

  it("refreshes and reacquires discovery once after 401, but never retries a second 401", async () => {
    await seed();
    const successState = state({
      calendarResponses: [
        json({ error: "unauthorized" }, 401),
        json({ items: [{ id: "provider", summary: "Calendar", accessRole: "reader" }] }),
      ],
    });
    await expect(service(successState).listCalendars(PRINCIPAL)).resolves.toMatchObject({
      calendars: [{ name: "Calendar" }],
    });
    expect(successState).toMatchObject({ calendarCalls: 2, refreshCalls: 1 });

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed();
    const rejectedState = state({
      calendarResponses: [json({ error: "unauthorized" }, 401), json({ error: "again" }, 401)],
    });
    await expectCode(service(rejectedState).listCalendars(PRINCIPAL), "unavailable");
    expect(rejectedState).toMatchObject({ calendarCalls: 2, refreshCalls: 1 });
  });

  it("marks invalid_grant reconnect during forced discovery refresh and exposes no calendars", async () => {
    await seed();
    const providerState = state({
      calendarResponses: [json({ error: "unauthorized" }, 401)],
      refreshResponse: json({ error: "invalid_grant" }, 400),
    });
    await expectCode(service(providerState).listCalendars(PRINCIPAL), "reconnect");
    expect(providerState).toMatchObject({ calendarCalls: 1, refreshCalls: 1 });
    expect(await testEnv.DB.prepare("SELECT status FROM connections").first()).toEqual({
      status: "reconnect_required",
    });
  });

  it("tells the owner of a calendar whose access lapsed to reconnect, and nobody else", async () => {
    await seed({ calendar: true });
    await insertPrincipal(OTHER_PRINCIPAL, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    await testEnv.DB.prepare(
      `UPDATE connections SET status = 'reconnect_required', refresh_lease_owner = NULL,
         refresh_lease_until = NULL, refresh_lease_generation = NULL,
         refresh_lease_token_version = NULL, discovery_lease_owner = NULL,
         discovery_lease_until = NULL, discovery_lease_generation = NULL,
         discovery_lease_token_version = NULL, updated_at = MAX(unixepoch(), updated_at)`,
    ).run();
    const providerState = state();
    const instance = service(providerState);
    const id = await sealEventId(
      "lapsed-event",
      { environment: "local", provider: "google", authorizationScopedCalendarId: CALENDAR },
      EVENT_KEY,
    );
    for (const attempt of [
      () => instance.listEvents(PRINCIPAL, CALENDAR, RANGE),
      () => instance.listChanges(PRINCIPAL, CALENDAR, {}),
      () => instance.event(PRINCIPAL, CALENDAR, "GET", id),
    ]) {
      await expect(attempt()).rejects.toMatchObject({
        code: "reconnect",
        detail: "connection_lapsed",
      });
    }
    await expectCode(instance.listEvents(OTHER_PRINCIPAL, CALENDAR, RANGE), "not_found");
    await expectCode(
      instance.listEvents(PRINCIPAL, "99999999-9999-4999-8999-999999999999", RANGE),
      "not_found",
    );
    expect(providerState).toMatchObject({ calendarCalls: 0, eventCalls: 0, refreshCalls: 0 });
  });

  it("returns no-connection discovery, rejects reconnect, and contains cursor sealing failures", async () => {
    const noConnection = state();
    await insertPrincipal();
    await expect(service(noConnection).listCalendars(PRINCIPAL)).resolves.toEqual({
      calendars: [],
    });
    await insertConnection();
    await testEnv.DB.prepare(
      `UPDATE connections SET status = 'reconnect_required', refresh_lease_owner = NULL,
         refresh_lease_until = NULL, refresh_lease_generation = NULL,
         refresh_lease_token_version = NULL, discovery_lease_owner = NULL,
         discovery_lease_until = NULL, discovery_lease_generation = NULL,
         discovery_lease_token_version = NULL, updated_at = MAX(unixepoch(), updated_at)`,
    ).run();
    await expectCode(service(noConnection).listCalendars(PRINCIPAL), "reconnect");

    await testEnv.DB.prepare("DELETE FROM principals").run();
    await seed({ calendar: true });
    const pageState = state({
      eventResponses: [json({ items: [], nextPageToken: "next" })],
    });
    await expectCode(
      service(pageState, {
        random: {
          bytes: () => {
            throw new Error("cursor random failed");
          },
        },
      }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "unavailable",
    );
    await expectCode(
      service(state({ eventResponses: [json({ items: [], nextPageToken: "next" })] }), {
        nowEpochSeconds: () => -1,
      }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "internal",
    );
  });

  it("uses a winner's completed mappings while waiting on another discovery lease", async () => {
    await seed();
    await testEnv.DB.prepare(
      `UPDATE connections SET discovery_lease_owner = 'winner-owner',
         discovery_lease_until = unixepoch() + 45,
         discovery_lease_generation = generation,
         discovery_lease_token_version = token_version,
         updated_at = MAX(unixepoch(), updated_at)`,
    ).run();
    let slept = false;
    const providerState = state();
    const instance = service(providerState, {
      sleep: async () => {
        if (slept) return;
        slept = true;
        await testEnv.DB.prepare(
          `UPDATE connections SET discovery_lease_owner = NULL, discovery_lease_until = NULL,
             discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
             discovery_version = discovery_version + 1,
             updated_at = MAX(unixepoch(), updated_at),
             last_provider_success_at = MAX(unixepoch(), updated_at)
           WHERE discovery_lease_owner = 'winner-owner'`,
        ).run();
      },
    });
    await expect(instance.listCalendars(PRINCIPAL)).resolves.toEqual({ calendars: [] });
    expect(providerState.calendarCalls).toBe(0);
  });

  it("observes a winner completing on the final bounded loser wait", async () => {
    await seed();
    await testEnv.DB.prepare(
      `UPDATE connections SET discovery_lease_owner = 'slow-winner',
         discovery_lease_until = unixepoch() + 45,
         discovery_lease_generation = generation,
         discovery_lease_token_version = token_version,
         updated_at = MAX(unixepoch(), updated_at)`,
    ).run();
    let sleeps = 0;
    const providerState = state();
    const instance = service(providerState, {
      sleep: async () => {
        if (++sleeps !== 5) return;
        await testEnv.DB.prepare(
          `UPDATE connections SET discovery_lease_owner = NULL, discovery_lease_until = NULL,
             discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
             discovery_version = discovery_version + 1,
             updated_at = MAX(unixepoch(), updated_at),
             last_provider_success_at = MAX(unixepoch(), updated_at)
           WHERE discovery_lease_owner = 'slow-winner'`,
        ).run();
      },
    });
    await expect(instance.listCalendars(PRINCIPAL)).resolves.toEqual({ calendars: [] });
    expect(sleeps).toBe(5);
    expect(providerState.calendarCalls).toBe(0);
  });

  it("fails unauthorized event locators before provider access and rejects a second Calendar 401", async () => {
    await seed({ calendar: true });
    const providerState = state();
    const instance = service(providerState);
    await expectCode(instance.listEvents(PRINCIPAL, OTHER_CALENDAR, RANGE), "not_found");
    await expectCode(instance.listEvents(OTHER_PRINCIPAL, CALENDAR, RANGE), "not_found");
    expect(providerState).toMatchObject({ eventCalls: 0, refreshCalls: 0 });

    providerState.eventResponses.push(
      json({ error: "unauthorized" }, 401),
      json({ error: "unauthorized-again" }, 401),
    );
    await expectCode(instance.listEvents(PRINCIPAL, CALENDAR, RANGE), "unavailable");
    expect(providerState).toMatchObject({ eventCalls: 2, refreshCalls: 1 });
  });

  it.each(["discovery", "events"] as const)(
    "maps provider network and timeout failures for %s",
    async (operation) => {
      await seed({ calendar: operation === "events" });
      const failed = state();
      const network = service(failed, {
        fetch: async () => {
          throw new TypeError("offline");
        },
      });
      await expectCode(
        operation === "events"
          ? network.listEvents(PRINCIPAL, CALENDAR, RANGE)
          : network.listCalendars(PRINCIPAL),
        "unavailable",
      );
      const stalled = service(state(), {
        fetch: async (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () => reject(new DOMException("aborted", "AbortError")),
              { once: true },
            );
          }),
        providerTimeoutMs: 1,
      });
      await expectCode(
        operation === "events"
          ? stalled.listEvents(PRINCIPAL, CALENDAR, RANGE)
          : stalled.listCalendars(PRINCIPAL),
        "unavailable",
      );
    },
  );

  it("uses default provider timeouts and default rate retry hints when dependencies omit both", async () => {
    await seed();
    const discoveryRate = state({
      calendarResponses: [json({ error: "rate" }, 429)],
    });
    await expect(
      service(discoveryRate, { providerTimeoutMs: 0 }).listCalendars(PRINCIPAL),
    ).rejects.toMatchObject({
      code: "rate",
      retryAfterSeconds: 1,
    });
    const success = state({ calendarResponses: [json({ items: [] })] });
    await expect(
      service(success, { providerTimeoutMs: 0 }).listCalendars(PRINCIPAL),
    ).resolves.toEqual({
      calendars: [],
      discovery: { omittedCount: 0, truncated: false },
    });

    await insertCalendar();
    const eventRate = state({ eventResponses: [json({ error: "rate" }, 429)] });
    await expect(
      service(eventRate, { providerTimeoutMs: 0 }).listEvents(PRINCIPAL, CALENDAR, RANGE),
    ).rejects.toMatchObject({ code: "rate", retryAfterSeconds: 1 });
    const eventSuccess = state({ eventResponses: [json({ items: [] })] });
    await expect(
      service(eventSuccess, { providerTimeoutMs: 0 }).listEvents(PRINCIPAL, CALENDAR, RANGE),
    ).resolves.toEqual({ events: [], next_cursor: null, omitted_count: 0 });
  });

  it("leaves out a malformed calendar and a malformed event interval, and counts each", async () => {
    await seed();
    const malformedCalendar = state({
      calendarResponses: [json({ items: [{ id: "provider", summary: "", accessRole: "reader" }] })],
    });
    await expect(service(malformedCalendar).listCalendars(PRINCIPAL)).resolves.toEqual({
      calendars: [],
      discovery: { omittedCount: 1, truncated: false },
    });
    expect(await testEnv.DB.prepare("SELECT 1 FROM calendars").first()).toBeNull();

    await insertCalendar();
    const malformedEvent = state({
      eventResponses: [
        json({
          items: [
            {
              id: "event",
              status: "confirmed",
              etag: '"1"',
              updated: "2026-01-01T00:00:00Z",
              start: { date: "2026-01-02" },
              end: { date: "2026-01-01" },
            },
          ],
        }),
      ],
    });
    await expect(service(malformedEvent).listEvents(PRINCIPAL, CALENDAR, RANGE)).resolves.toEqual({
      events: [],
      next_cursor: null,
      omitted_count: 1,
    });
  });

  it("contains a losing discovery sleep failure without crossing the provider boundary", async () => {
    await seed();
    await testEnv.DB.prepare(
      `UPDATE connections SET discovery_lease_owner = 'other-owner',
         discovery_lease_until = unixepoch() + 45,
         discovery_lease_generation = generation,
         discovery_lease_token_version = token_version,
         updated_at = MAX(unixepoch(), updated_at)`,
    ).run();
    const providerState = state();
    await expectCode(
      service(providerState, {
        sleep: async () => {
          throw new Error("sleep failed");
        },
      }).listCalendars(PRINCIPAL),
      "internal",
    );
    expect(providerState.calendarCalls).toBe(0);
  });

  it("fails event authorization coherently when token snapshots or refreshed grants change", async () => {
    await seed({ calendar: true });
    const providerState = state({ eventResponses: [json({ error: "unauthorized" }, 401)] });
    const snapshot = {
      principalId: PRINCIPAL,
      connectionId: CONNECTION,
      generation: 1,
      tokenVersion: 1,
      principalGeneration: 1,
    } as const;
    const grant = { accessToken: "access", ...snapshot } as const;
    const absent = {
      loadForPrincipal: async () => null,
    } as unknown as GoogleAccessTokens;
    await expectCode(
      service(providerState, { accessTokens: absent }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "not_found",
    );
    const mismatchedSnapshot = {
      loadForPrincipal: async () => ({ ...snapshot, generation: 2 }),
    } as unknown as GoogleAccessTokens;
    await expectCode(
      service(providerState, { accessTokens: mismatchedSnapshot }).listEvents(
        PRINCIPAL,
        CALENDAR,
        RANGE,
      ),
      "not_found",
    );
    let accesses = 0;
    const changedGrant = {
      loadForPrincipal: async () => snapshot,
      assertCurrent: async () => undefined,
      access: async () =>
        ++accesses === 1 ? grant : { ...grant, generation: 2, accessToken: "changed" },
    } as unknown as GoogleAccessTokens;
    await expectCode(
      service(providerState, { accessTokens: changedGrant }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "not_found",
    );
  });

  it("contains unexpected token and current-grant dependency failures", async () => {
    await seed({ calendar: true });
    const snapshot = {
      principalId: PRINCIPAL,
      connectionId: CONNECTION,
      generation: 1,
      tokenVersion: 1,
      principalGeneration: 1,
    } as const;
    const grant = { accessToken: "access", ...snapshot } as const;
    const liveFailure = new LiveGoogleCalendarError("conflict");
    const loadFails = {
      loadForPrincipal: async () => {
        throw liveFailure;
      },
    } as unknown as GoogleAccessTokens;
    await expect(
      service(state(), { accessTokens: loadFails }).listCalendars(PRINCIPAL),
    ).rejects.toBe(liveFailure);
    const assertFails = {
      loadForPrincipal: async () => snapshot,
      access: async () => grant,
      assertCurrent: async () => {
        throw new Error("assert failed");
      },
    } as unknown as GoogleAccessTokens;
    await expectCode(
      service(state({ eventResponses: [json({ items: [] })] }), {
        accessTokens: assertFails,
      }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "internal",
    );
  });

  it.each([
    ["status", (row: Record<string, unknown>) => ({ ...row, status: "broken" })],
    ["generation", (row: Record<string, unknown>) => ({ ...row, generation: 0 })],
    ["token version", (row: Record<string, unknown>) => ({ ...row, token_version: 0 })],
    ["discovery version", (row: Record<string, unknown>) => ({ ...row, discovery_version: -1 })],
    ["principal epoch", (row: Record<string, unknown>) => ({ ...row, principal_generation: 2 })],
    ["connection UUID", (row: Record<string, unknown>) => ({ ...row, id: "invalid" })],
    ["principal UUID", (row: Record<string, unknown>) => ({ ...row, principal_id: "invalid" })],
  ] as const)("fails closed on corrupt authorized D1 %s", async (_name, mutate) => {
    await seed({ calendar: true });
    const providerState = state();
    const db = rowFaultDatabase(mutate);
    await expectCode(
      service(providerState, {
        db,
        accessTokens: accessTokens(testEnv.DB, provider(providerState)),
      }).listEvents(PRINCIPAL, CALENDAR, RANGE),
      "internal",
    );
    expect(providerState.eventCalls).toBe(0);
  });

  it.each([
    ["status", (row: Record<string, unknown>) => ({ ...row, status: "broken" })],
    ["DEK IV", (row: Record<string, unknown>) => ({ ...row, dek_iv: "" })],
    ["wrapped DEK", (row: Record<string, unknown>) => ({ ...row, wrapped_dek: "" })],
    ["payload IV", (row: Record<string, unknown>) => ({ ...row, payload_iv: "" })],
    ["ciphertext", (row: Record<string, unknown>) => ({ ...row, ciphertext: "" })],
    ["lease owner", (row: Record<string, unknown>) => ({ ...row, refresh_lease_owner: "" })],
    ["lease time", (row: Record<string, unknown>) => ({ ...row, refresh_lease_until: -1 })],
    [
      "lease generation",
      (row: Record<string, unknown>) => ({ ...row, refresh_lease_generation: 0 }),
    ],
    ["lease token", (row: Record<string, unknown>) => ({ ...row, refresh_lease_token_version: 0 })],
    ["partial lease", (row: Record<string, unknown>) => ({ ...row, refresh_lease_until: 1 })],
    ["connection UUID", (row: Record<string, unknown>) => ({ ...row, id: "bad" })],
    ["principal UUID", (row: Record<string, unknown>) => ({ ...row, principal_id: "bad" })],
    ["generation type", (row: Record<string, unknown>) => ({ ...row, generation: "1" })],
    ["generation", (row: Record<string, unknown>) => ({ ...row, generation: 0 })],
    ["token version", (row: Record<string, unknown>) => ({ ...row, token_version: 0 })],
    [
      "envelope version",
      (row: Record<string, unknown>) => ({ ...row, envelope_schema_version: 0 }),
    ],
    ["key version", (row: Record<string, unknown>) => ({ ...row, key_version: 0 })],
    [
      "lease authority generation",
      (row: Record<string, unknown>) => ({
        ...row,
        refresh_lease_owner: "owner",
        refresh_lease_until: 9999999999,
        refresh_lease_generation: 2,
        refresh_lease_token_version: 1,
      }),
    ],
    [
      "lease authority token",
      (row: Record<string, unknown>) => ({
        ...row,
        refresh_lease_owner: "owner",
        refresh_lease_until: 9999999999,
        refresh_lease_generation: 1,
        refresh_lease_token_version: 2,
      }),
    ],
    ["updated time type", (row: Record<string, unknown>) => ({ ...row, updated_at: "now" })],
    ["updated time", (row: Record<string, unknown>) => ({ ...row, updated_at: -1 })],
    ["database time", (row: Record<string, unknown>) => ({ ...row, database_now: -1 })],
    ["principal epoch", (row: Record<string, unknown>) => ({ ...row, principal_generation: 2 })],
  ] as const)("fails closed on corrupt token-custody D1 %s", async (_name, mutate) => {
    await seed();
    const db = tokenRowFaultDatabase(mutate);
    await expect(
      accessTokens(db, provider(state())).loadForPrincipal(PRINCIPAL),
    ).rejects.toMatchObject({
      code: "internal",
    });
  });

  it("stores Google's colour, selection and the person's own name, and replaces them", async () => {
    await seed();
    const item = { id: "provider", summary: "Shared", accessRole: "writerWithoutPrivateAccess" };
    const providerState = state({
      calendarResponses: [
        json({
          items: [
            { ...item, summaryOverride: "Mine", selected: true, backgroundColor: "#0088AA" },
            { id: "plain", summary: "Plain", accessRole: "reader", backgroundColor: "teal" },
          ],
        }),
        json({ items: [{ ...item, backgroundColor: "#ffffff" }] }),
      ],
    });
    const display = (calendars: Awaited<ReturnType<LiveGoogleCalendar["listCalendars"]>>) =>
      calendars.calendars.map(({ name, can_write, is_selected, color }) => ({
        name,
        can_write,
        is_selected,
        color,
      }));
    expect(display(await service(providerState).listCalendars(PRINCIPAL))).toEqual([
      { name: "Mine", can_write: true, is_selected: true, color: "#0088aa" },
      { name: "Plain", can_write: false, is_selected: false, color: null },
    ]);
    const later = service(providerState, { db: clockDatabase(301), nowEpochSeconds: () => 1 });
    expect(display(await later.listCalendars(PRINCIPAL))).toEqual([
      { name: "Shared", can_write: true, is_selected: false, color: "#ffffff" },
    ]);
    expect(providerState.calendarCalls).toBe(2);
  });

  it.each([{ is_primary: 2 }, { is_selected: 2 }])(
    "fails closed on a corrupt persisted public calendar row %j",
    async (corruption) => {
      await seed();
      const providerState = state({
        calendarResponses: [
          json({ items: [{ id: "provider", summary: "Calendar", accessRole: "reader" }] }),
        ],
      });
      await expectCode(
        service(providerState, {
          db: calendarReadFaultDatabase(undefined, corruption),
          accessTokens: accessTokens(testEnv.DB, provider(providerState)),
        }).listCalendars(PRINCIPAL),
        "internal",
      );
    },
  );

  it("carries availability, the kind of entry and the person's own answer on live reads", async () => {
    await seed({ calendar: true });
    const base = {
      status: "confirmed",
      etag: '"1"',
      updated: "2026-01-01T00:00:00Z",
      start: { dateTime: "2026-01-02T10:00:00Z" },
      end: { dateTime: "2026-01-02T11:00:00Z" },
    };
    const providerState = state({
      eventResponses: [
        json({
          items: [
            {
              ...base,
              id: "declined-private",
              attendees: [{ self: true, responseStatus: "declined", email: "me@private.test" }],
            },
            {
              ...base,
              id: "office-private",
              eventType: "workingLocation",
              transparency: "transparent",
            },
            { ...base, id: "plain-private" },
          ],
        }),
      ],
    });
    const page = await service(providerState).listEvents(PRINCIPAL, CALENDAR, RANGE);
    expect(page.omitted_count).toBe(0);
    expect(
      page.events.map(({ transparency, event_type, self_response }) => ({
        transparency,
        event_type,
        self_response,
      })),
    ).toEqual([
      { transparency: "opaque", event_type: "default", self_response: "declined" },
      { transparency: "transparent", event_type: "working_location", self_response: null },
      { transparency: "opaque", event_type: "default", self_response: null },
    ]);
    expect(JSON.stringify(page)).not.toContain("private");
  });

  it.each([
    ["reconnect", "reconnect"],
    ["conflict", "conflict"],
    ["rate_limited", "rate"],
    ["unavailable", "unavailable"],
    ["internal", "internal"],
  ] as const)("maps access-token dependency %s failures", async (tokenCode, expectedCode) => {
    await insertPrincipal();
    const providerState = state();
    const tokens = {
      loadForPrincipal: async () => {
        throw new GoogleAccessTokenError(tokenCode, 7);
      },
    } as unknown as GoogleAccessTokens;
    await expectCode(
      service(providerState, { accessTokens: tokens }).listCalendars(PRINCIPAL),
      expectedCode,
    );
  });

  it("validates both dedicated key dependencies", () => {
    expect(() => service(state(), { cursorKey: new Uint8Array(31) })).toThrow(TypeError);
    expect(() => service(state(), { eventIdKey: new Uint8Array(31) })).toThrow(TypeError);
  });

  it("contains random, UUID, sleep, and D1 failures as generic typed errors", async () => {
    await seed();
    const providerState = state({
      calendarResponses: [
        json({ items: [{ id: "provider", summary: "Calendar", accessRole: "reader" }] }),
      ],
    });
    await expectCode(
      service(providerState, {
        random: {
          bytes: () => {
            throw new Error("random failed");
          },
        },
      }).listCalendars(PRINCIPAL),
      "internal",
    );
    await expectCode(
      service(providerState, { uuid: () => "not-a-uuid" }).listCalendars(PRINCIPAL),
      "internal",
    );
    const failedDb = new Proxy(testEnv.DB, {
      get(target, property): unknown {
        if (property === "prepare")
          return () => {
            throw new Error("D1 failed");
          };
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? (value.bind(target) as unknown) : value;
      },
    });
    await expectCode(
      service(providerState, {
        db: failedDb,
        accessTokens: accessTokens(testEnv.DB, provider(providerState)),
      }).listCalendars(PRINCIPAL),
      "internal",
    );
    expect(LiveGoogleCalendarError).toBeDefined();
  });
});
