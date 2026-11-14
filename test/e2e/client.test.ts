import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CalendarServiceClient,
  type CalendarServiceHost,
  type ServiceRequest,
  type ServiceResponse,
  type ServiceTransport,
} from "../../client/src/index";
import type { Env } from "../../src/env";
import type { FakeGoogleConfiguration } from "../support/fake-google";

const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher };
const fake = bindings.FAKE_GOOGLE;
const ORIGIN = "http://127.0.0.1:8787";
// The client sends a person only to Google's own consent page. This Worker is
// configured for the fake provider, so the test presents the fake's page under
// Google's address and the stand-in person visits the fake again.
const FAKE_CONSENT = "http://127.0.0.1:9797/authorize";
const GOOGLE_CONSENT = "https://accounts.google.com/o/oauth2/v2/auth";

async function worker(url: string, request: ServiceRequest): Promise<ServiceResponse> {
  const response = await exports.default.fetch(
    new Request(url, {
      method: request.method,
      headers: request.headers,
      signal: request.signal,
      ...(request.body === undefined ? {} : { body: request.body }),
    }),
  );
  if (!url.endsWith("/start") || !response.ok) return response;
  const started = await response.json<{ authorization_url: string }>();
  expect(started.authorization_url.startsWith(`${FAKE_CONSENT}?`)).toBe(true);
  return Response.json(
    {
      ...started,
      authorization_url: started.authorization_url.replace(FAKE_CONSENT, GOOGLE_CONSENT),
    },
    { status: response.status },
  );
}

async function configure(value: FakeGoogleConfiguration): Promise<void> {
  const response = await fake.fetch("https://fake-google-control.test/configure", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  expect(response.status).toBe(204);
}

/** The published client, speaking to this Worker as the Obsidian plugin does. */
function obsidianClient() {
  const stored = new Map<string, string>();
  const credential = { value: null as string | null };
  const requests: { path: string; authorization: string | undefined }[] = [];
  let confirmationCode: string | undefined;

  const transport: ServiceTransport = async (url, request) => {
    requests.push({
      path: new URL(url).pathname,
      authorization: request.headers["Authorization"],
    });
    return worker(url, request);
  };
  const host: CalendarServiceHost = {
    clientKind: "obsidian",
    deviceName: "Client contract test",
    credentials: {
      load: () => Promise.resolve(credential.value),
      save: (value) => {
        credential.value = value;
        return Promise.resolve();
      },
      clear: () => {
        credential.value = null;
        return Promise.resolve();
      },
    },
    openWindow: () => ({
      // Stands in for the person: consents at Google and reads the code shown.
      async show(url) {
        const consent = await fake.fetch(
          new Request(url.replace(GOOGLE_CONSENT, FAKE_CONSENT), { redirect: "manual" }),
        );
        const callback = await exports.default.fetch(
          new Request(consent.headers.get("location") ?? "missing:"),
        );
        confirmationCode = /class="code"[^>]*>([2-9A-HJ-NP-Z]{8})</u.exec(
          await callback.text(),
        )?.[1];
      },
      close: () => undefined,
    }),
  };
  const client = new CalendarServiceClient({
    origin: ORIGIN,
    host,
    transport,
    storage: {
      getItem: (key) => stored.get(key) ?? null,
      setItem: (key, value) => void stored.set(key, value),
      removeItem: (key) => void stored.delete(key),
    },
  });
  return {
    client,
    credential,
    requests,
    signIn: async () => {
      const finished = client.signIn();
      await vi.waitFor(() => expect(client.getSnapshot().awaitingCode).toBe(true), 8_000);
      client.submitCode(confirmationCode ?? "");
      await finished;
    },
  };
}

beforeEach(async () => {
  const reset = await fake.fetch("https://fake-google-control.test/reset", { method: "POST" });
  expect(reset.status).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

describe("the published client against this Worker", () => {
  it("signs in, connects, reads calendars and events, and signs out", async () => {
    await configure({
      calendarEnabled: true,
      calendarPages: [
        {
          items: [
            { id: "provider-work", summary: "Work", accessRole: "owner", primary: true },
            { id: "provider-team", summary: "Team", accessRole: "reader", selected: true },
          ],
        },
      ],
      eventPages: [
        {
          calendarId: "provider-work",
          nextPageToken: "second-page",
          items: [
            {
              id: "provider-timed",
              status: "confirmed",
              etag: '"1"',
              updated: "2026-01-01T10:00:00Z",
              summary: "Timed",
              htmlLink: "https://www.google.com/calendar/event?eid=abc",
              start: { dateTime: "2026-01-02T10:00:00Z" },
              end: { dateTime: "2026-01-02T11:00:00Z" },
            },
          ],
        },
        {
          calendarId: "provider-work",
          items: [
            {
              id: "provider-all-day",
              status: "confirmed",
              etag: '"1"',
              updated: "2026-01-01T10:00:00Z",
              summary: "All day",
              start: { date: "2026-01-03" },
              end: { date: "2026-01-04" },
            },
          ],
        },
      ],
    });
    const { client, credential, requests, signIn } = obsidianClient();

    await signIn();
    expect(client.getSnapshot()).toMatchObject({ failure: null, connection: null, calendars: [] });
    expect(client.getSnapshot().sessionId).toEqual(expect.any(String));
    expect(credential.value).toEqual(expect.any(String));
    // A bearer client never relies on a cookie: every signed-in request carries it.
    expect(requests.at(-1)).toEqual({
      path: "/v1/connections",
      authorization: `Bearer ${credential.value ?? ""}`,
    });

    await client.connect();
    const connected = client.getSnapshot();
    expect(connected.failure).toBeNull();
    expect(connected.connection).toMatchObject({ status: "active" });
    expect(
      connected.calendars.map(({ name, can_write, is_primary }) => [name, can_write, is_primary]),
    ).toEqual([
      ["Work", true, true],
      ["Team", false, false],
    ]);
    expect(connected.selected).toEqual(connected.calendars.map(({ id }) => id));

    const work = connected.calendars[0]?.id ?? "";
    const read = await client.events(
      work,
      new Date("2026-01-01T00:00:00Z"),
      new Date("2026-01-31T00:00:00Z"),
      new AbortController().signal,
    );
    expect(read.omitted).toBe(0);
    expect(read.events.map(({ title, start }) => [title, start.kind])).toEqual([
      ["Timed", "date_time"],
      ["All day", "date"],
    ]);
    expect(read.events[0]).toMatchObject({
      calendar_id: work,
      web_link: "https://www.google.com/calendar/event?eid=abc",
    });

    await client.signOut();
    expect(client.getSnapshot()).toMatchObject({ sessionId: null, calendars: [], failure: null });
    expect(credential.value).toBeNull();
  }, 30_000);

  it("resumes a stored session without signing in again", async () => {
    const first = obsidianClient();
    await first.signIn();
    const sessionId = first.client.getSnapshot().sessionId;

    // A restart keeps only what the host stored: the flag and the credential.
    const second = obsidianClient();
    second.credential.value = first.credential.value;
    await second.client.restore();
    expect(second.client.getSnapshot().sessionId).toBeNull();

    const storage = new Map([["tasknotes:google-calendar-signed-in:v1", "1"]]);
    const resumed = new CalendarServiceClient({
      origin: ORIGIN,
      host: {
        clientKind: "obsidian",
        deviceName: "Client contract test",
        credentials: {
          load: () => Promise.resolve(first.credential.value),
          save: () => Promise.resolve(),
          clear: () => Promise.resolve(),
        },
        openWindow: () => null,
      },
      transport: worker,
      storage: {
        getItem: (key) => storage.get(key) ?? null,
        setItem: (key, value) => void storage.set(key, value),
        removeItem: (key) => void storage.delete(key),
      },
    });
    await resumed.restore();
    expect(resumed.getSnapshot()).toMatchObject({ sessionId, failure: null });
  }, 30_000);
});
