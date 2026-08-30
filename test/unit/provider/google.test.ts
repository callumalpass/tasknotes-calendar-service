import { describe, expect, it, vi } from "vitest";

import {
  googleProductionConfiguration,
  googleTestConfiguration,
  listGoogleCalendarsPage,
  listGoogleEventsPage,
  refreshGoogleToken,
  revokeGoogleTokenBestEffort,
} from "../../../src/provider/google";

const testConfiguration = googleTestConfiguration({
  tokenEndpoint: "http://oauth.test/token",
  revocationEndpoint: "http://oauth.test/revoke",
  calendarApiOrigin: "http://calendar.test",
});

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

function formBody(init: RequestInit | undefined): string {
  if (!(init?.body instanceof URLSearchParams)) throw new Error("expected a form body");
  return init.body.toString();
}

function fakeFetch(
  implementation: (url: URL, init: RequestInit | undefined) => Response | Promise<Response>,
): typeof fetch {
  return async (input, init) =>
    implementation(new URL(input instanceof Request ? input.url : input.toString()), init);
}

const calendar = {
  id: "opaque/calendar?identifier",
  summary: "Work <script>alert(1)</script>",
  description: "Untrusted but inert text",
  timeZone: "Europe/London",
  accessRole: "owner",
  primary: true,
  selected: true,
  etag: "excluded",
};

const timedEvent = {
  id: "event-1",
  status: "confirmed",
  summary: "DST boundary",
  description: "description",
  location: "location",
  transparency: "transparent",
  start: { dateTime: "2026-03-29T00:30:00Z", timeZone: "Europe/London" },
  end: { dateTime: "2026-03-29T02:30:00+01:00", timeZone: "Europe/London" },
  attendees: [{ email: "private@example.test" }],
  organizer: { email: "private@example.test" },
  conferenceData: { entryPoints: [] },
  htmlLink: "https://provider.test/private",
  recurrence: ["RRULE:FREQ=DAILY"],
};

const eventsRequest = {
  configuration: testConfiguration,
  accessToken: "access-secret",
  calendarId: "opaque/calendar?identifier",
  timeMin: "2026-03-01T00:00:00Z",
  timeMax: "2026-04-01T00:00:00Z",
};

describe("Google provider HTTP boundary", () => {
  it("pins production HTTPS Google origins and requires an explicit test factory", () => {
    const production = googleProductionConfiguration();
    expect(production.tokenEndpoint.href).toBe("https://oauth2.googleapis.com/token");
    expect(production.revocationEndpoint.href).toBe("https://oauth2.googleapis.com/revoke");
    expect(production.calendarApiOrigin.href).toBe("https://www.googleapis.com/");

    production.tokenEndpoint.href = "http://attacker.test/";
    expect(production.tokenEndpoint.href).toBe("https://oauth2.googleapis.com/token");
    expect(() =>
      googleTestConfiguration({
        tokenEndpoint: "file:///token",
        revocationEndpoint: "http://oauth.test/revoke",
        calendarApiOrigin: "http://calendar.test",
      }),
    ).toThrow(TypeError);
    expect(() =>
      googleTestConfiguration({
        tokenEndpoint: "http://oauth.test/token",
        revocationEndpoint: "http://oauth.test/revoke",
        calendarApiOrigin: "http://calendar.test/prefix",
      }),
    ).toThrow(TypeError);
  });

  it("refreshes with a form body and validates the bounded token response", async () => {
    let observedUrl: URL | undefined;
    let observedBody = "";
    const result = await refreshGoogleToken({
      configuration: testConfiguration,
      fetch: fakeFetch((url, init) => {
        observedUrl = url;
        observedBody = formBody(init);
        return json({
          access_token: "new-access-secret",
          expires_in: 3600,
          token_type: "Bearer",
          scope: "calendar.readonly",
          refresh_token: "rotated-refresh-secret",
        });
      }),
      clientId: "client-id",
      clientSecret: "client-secret",
      refreshToken: "old-refresh-secret",
    });

    expect(result).toEqual({
      ok: true,
      value: {
        accessToken: "new-access-secret",
        expiresInSeconds: 3600,
        scope: "calendar.readonly",
        refreshToken: "rotated-refresh-secret",
      },
    });
    expect(observedUrl?.href).toBe("http://oauth.test/token");
    expect(observedUrl?.href).not.toContain("secret");
    expect(new URLSearchParams(observedBody)).toEqual(
      new URLSearchParams({
        client_id: "client-id",
        client_secret: "client-secret",
        refresh_token: "old-refresh-secret",
        grant_type: "refresh_token",
      }),
    );
  });

  it("rejects malformed and oversized refresh responses without exposing their contents", async () => {
    for (const payload of [
      { access_token: "secret", expires_in: "3600", token_type: "Bearer" },
      { access_token: "x".repeat(16_385), expires_in: 3600, token_type: "Bearer" },
      { access_token: "secret", expires_in: 3600, token_type: "MAC" },
    ]) {
      const result = await refreshGoogleToken({
        configuration: testConfiguration,
        fetch: fakeFetch(() => json(payload)),
        clientId: "client",
        clientSecret: "client-secret",
        refreshToken: "refresh-secret",
      });
      expect(result).toEqual({
        ok: false,
        error: { code: "invalid_response", message: "Provider returned an invalid response." },
      });
      expect(JSON.stringify(result)).not.toContain("secret");
    }
  });

  it("revokes best effort without putting the token in the URL", async () => {
    let requestUrl = "";
    let requestBody = "";
    const result = await revokeGoogleTokenBestEffort({
      configuration: testConfiguration,
      token: "revocation-secret",
      fetch: fakeFetch((url, init) => {
        requestUrl = url.href;
        requestBody = formBody(init);
        return new Response(null, { status: 200 });
      }),
    });
    expect(result).toEqual({ ok: true, value: undefined });
    expect(requestUrl).toBe("http://oauth.test/revoke");
    expect(requestBody).toBe("token=revocation-secret");
  });

  it("constructs a calendar page URL from an opaque token and normalizes a strict shape", async () => {
    let requested: URL | undefined;
    const result = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access-secret",
      pageToken: "opaque+/=?& token",
      fetch: fakeFetch((url, init) => {
        requested = url;
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer access-secret");
        expect(init?.redirect).toBe("error");
        return json({ items: [calendar], nextPageToken: "next+/=?& token" });
      }),
    });

    expect(requested?.origin).toBe("http://calendar.test");
    expect(requested?.pathname).toBe("/calendar/v3/users/me/calendarList");
    expect(requested?.searchParams.get("pageToken")).toBe("opaque+/=?& token");
    expect(requested?.searchParams.get("maxResults")).toBe("250");
    expect(result).toEqual({
      ok: true,
      value: {
        items: [
          {
            id: "opaque/calendar?identifier",
            name: "Work <script>alert(1)</script>",
            description: "Untrusted but inert text",
            timeZone: "Europe/London",
            access: "owner",
            primary: true,
            selected: true,
          },
        ],
        nextPageToken: "next+/=?& token",
      },
    });
  });

  it("builds an events URL locally and excludes provider-private fields", async () => {
    let requested: URL | undefined;
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      pageToken: "opaque+/=?& token",
      fetch: fakeFetch((url) => {
        requested = url;
        return json({ items: [timedEvent], nextPageToken: "next-token" });
      }),
    });

    expect(requested?.pathname).toBe(
      "/calendar/v3/calendars/opaque%2Fcalendar%3Fidentifier/events",
    );
    expect(requested?.searchParams.get("pageToken")).toBe("opaque+/=?& token");
    expect(requested?.searchParams.get("singleEvents")).toBe("true");
    expect(requested?.searchParams.get("showDeleted")).toBe("true");
    expect(requested?.searchParams.get("orderBy")).toBe("startTime");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected successful event page");
    expect(result.value.items[0]).toEqual({
      id: "event-1",
      status: "confirmed",
      title: "DST boundary",
      description: "description",
      location: "location",
      transparency: "transparent",
      start: {
        kind: "timed",
        dateTime: "2026-03-29T00:30:00Z",
        timeZone: "Europe/London",
      },
      end: {
        kind: "timed",
        dateTime: "2026-03-29T02:30:00+01:00",
        timeZone: "Europe/London",
      },
    });
    const serialized = JSON.stringify(result.value);
    for (const excluded of ["attendees", "organizer", "conference", "htmlLink", "RRULE"]) {
      expect(serialized).not.toContain(excluded);
    }
  });

  it("preserves exclusive all-day ends and recurrence-instance original starts", async () => {
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      fetch: fakeFetch(() =>
        json({
          items: [
            {
              id: "all-day",
              status: "tentative",
              start: { date: "2024-02-29" },
              end: { date: "2024-03-02" },
            },
            {
              id: "cancelled-instance",
              status: "cancelled",
              recurringEventId: "opaque-series-id",
              originalStartTime: {
                dateTime: "2026-03-10T09:00:00-04:00",
                timeZone: "America/New_York",
              },
            },
          ],
        }),
      ),
    });
    expect(result).toMatchObject({
      ok: true,
      value: {
        items: [
          {
            status: "tentative",
            start: { kind: "all_day", date: "2024-02-29" },
            end: { kind: "all_day", date: "2024-03-02" },
          },
          {
            status: "cancelled",
            recurringEventId: "opaque-series-id",
            originalStart: {
              kind: "timed",
              dateTime: "2026-03-10T09:00:00-04:00",
              timeZone: "America/New_York",
            },
          },
        ],
      },
    });
  });

  it.each([
    [{ date: "2026-03-01", dateTime: "2026-03-01T00:00:00Z" }, { date: "2026-03-02" }],
    [{ date: "2026-02-30" }, { date: "2026-03-02" }],
    [{ date: "2026-03-01", timeZone: "UTC" }, { date: "2026-03-02" }],
    [{ dateTime: "2026-03-01T00:00:00" }, { dateTime: "2026-03-01T01:00:00Z" }],
    [
      { dateTime: "2026-03-01T00:00:00Z", timeZone: "Not/AZone" },
      { dateTime: "2026-03-01T01:00:00Z" },
    ],
    [
      { dateTime: "2026-03-01T00:00:00Z", timeZone: "America/New_York" },
      { dateTime: "2026-03-01T01:00:00Z" },
    ],
    [{ date: "2026-03-01" }, { dateTime: "2026-03-02T00:00:00Z" }],
    [{ dateTime: "2026-03-01T02:00:00Z" }, { dateTime: "2026-03-01T01:00:00Z" }],
  ])("rejects malformed or conflicting date boundaries", async (start, end) => {
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      fetch: fakeFetch(() => json({ items: [{ id: "bad", status: "confirmed", start, end }] })),
    });
    expect(result).toEqual({
      ok: false,
      error: { code: "invalid_response", message: "Provider returned an invalid response." },
    });
  });

  it("rejects event ranges beyond the server-owned 93-day bound before fetch", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      timeMin: "2026-01-01T00:00:00Z",
      timeMax: "2026-04-05T00:00:00Z",
      fetch: fetcher,
    });
    expect(result).toMatchObject({ ok: false, error: { code: "invalid_request" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects repeated and oversized page tokens and too many or huge items", async () => {
    const repeated = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      pageToken: "same",
      fetch: fakeFetch(() => json({ items: [], nextPageToken: "same" })),
    });
    expect(repeated).toMatchObject({ ok: false, error: { code: "invalid_response" } });

    const oversizedInput = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      pageToken: "x".repeat(8_193),
      fetch: fakeFetch(() => {
        throw new Error("must not fetch");
      }),
    });
    expect(oversizedInput).toMatchObject({ ok: false, error: { code: "invalid_request" } });

    const tooMany = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      fetch: fakeFetch(() => json({ items: Array.from({ length: 251 }, () => calendar) })),
    });
    expect(tooMany).toMatchObject({ ok: false, error: { code: "invalid_response" } });

    const huge = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      fetch: fakeFetch(() => json({ items: [{ ...calendar, summary: "x".repeat(2_049) }] })),
    });
    expect(huge).toMatchObject({ ok: false, error: { code: "invalid_response" } });
  });

  it.each([
    [new Response("not json", { headers: { "content-type": "text/html" } }), "invalid_response"],
    [new Response("{", { headers: { "content-type": "application/json" } }), "invalid_response"],
    [
      new Response("x".repeat(1_048_577), { headers: { "content-type": "application/json" } }),
      "invalid_response",
    ],
  ])("contains malformed and oversized response bodies", async (response, code) => {
    const result = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      fetch: fakeFetch(() => response),
    });
    expect(result).toMatchObject({ ok: false, error: { code } });
  });

  it("maps bounded retry errors without leaking hostile error bodies", async () => {
    const limited = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access-secret",
      fetch: fakeFetch(() =>
        json({ error: `access-secret ${"x".repeat(20_000)}` }, 429, { "retry-after": "999999" }),
      ),
    });
    expect(limited).toEqual({
      ok: false,
      error: {
        code: "rate_limited",
        message: "Provider rate limit was reached.",
        retryAfterSeconds: 3600,
      },
    });
    expect(JSON.stringify(limited)).not.toContain("access-secret");

    const unavailable = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      fetch: fakeFetch(() => json({ private: "body" }, 503)),
    });
    expect(unavailable).toEqual({
      ok: false,
      error: { code: "unavailable", message: "Provider is temporarily unavailable." },
    });
  });

  it("bounds request duration and distinguishes network failure", async () => {
    vi.useFakeTimers();
    try {
      const pending = listGoogleCalendarsPage({
        configuration: testConfiguration,
        accessToken: "access",
        timeoutMs: 10,
        fetch: fakeFetch(
          (_url, init) =>
            new Promise((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () =>
                reject(new DOMException("aborted", "AbortError")),
              );
            }),
        ),
      });
      await vi.advanceTimersByTimeAsync(11);
      await expect(pending).resolves.toMatchObject({ ok: false, error: { code: "timeout" } });
    } finally {
      vi.useRealTimers();
    }

    const network = await listGoogleCalendarsPage({
      configuration: testConfiguration,
      accessToken: "access",
      fetch: fakeFetch(() => {
        throw new Error("access-secret must not escape");
      }),
    });
    expect(network).toEqual({
      ok: false,
      error: { code: "network", message: "Provider request failed." },
    });
  });
});
