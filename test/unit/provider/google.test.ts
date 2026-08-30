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

function stalledResponse(status: number, contentType?: string): Response {
  const headers = contentType === undefined ? undefined : { "content-type": contentType };
  return new Response(
    new ReadableStream({
      cancel: () => new Promise<void>(() => undefined),
    }),
    { status, ...(headers === undefined ? {} : { headers }) },
  );
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
  updated: "2026-03-28T12:34:56.123Z",
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

  it("maps invalid_grant refresh failures to generic unauthorized without leaking descriptions", async () => {
    const result = await refreshGoogleToken({
      configuration: testConfiguration,
      fetch: fakeFetch(() =>
        json(
          {
            error: "invalid_grant",
            error_description: "refresh-secret was revoked for private@example.test",
          },
          400,
        ),
      ),
      clientId: "client",
      clientSecret: "client-secret",
      refreshToken: "refresh-secret",
    });

    expect(result).toEqual({
      ok: false,
      error: { code: "unauthorized", message: "Provider authorization failed." },
    });
    expect(JSON.stringify(result)).not.toContain("refresh-secret");
    expect(JSON.stringify(result)).not.toContain("private@example.test");
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
    expect(requested?.searchParams.get("fields")).toBe(
      "nextPageToken,items(id,summary,description,timeZone,accessRole,primary,selected)",
    );
    for (const excluded of ["etag", "conferenceProperties", "notificationSettings"]) {
      expect(requested?.searchParams.get("fields")).not.toContain(excluded);
    }
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
    expect(requested?.searchParams.get("fields")).toBe(
      "nextPageToken,items(id,status,updated,summary,description,location,transparency,start(date,dateTime,timeZone),end(date,dateTime,timeZone),recurringEventId,originalStartTime(date,dateTime,timeZone))",
    );
    for (const excluded of [
      "attendees",
      "organizer",
      "conferenceData",
      "htmlLink",
      "recurrence",
      "extendedProperties",
    ]) {
      expect(requested?.searchParams.get("fields")).not.toContain(excluded);
    }
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected successful event page");
    expect(result.value.items[0]).toEqual({
      id: "event-1",
      status: "confirmed",
      updatedAt: "2026-03-28T12:34:56.123Z",
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
              updated: "2024-02-28T20:00:00Z",
              start: { date: "2024-02-29" },
              end: { date: "2024-03-02" },
            },
            {
              id: "cancelled-instance",
              status: "cancelled",
              updated: "2026-03-11T12:00:00Z",
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
            recurrence: {
              seriesId: "opaque-series-id",
              originalStart: {
                kind: "timed",
                dateTime: "2026-03-10T09:00:00-04:00",
                timeZone: "America/New_York",
              },
            },
          },
        ],
      },
    });
  });

  it.each([undefined, "", "not-an-instant", "2026-02-30T00:00:00Z"])(
    "rejects missing or malformed required updated values",
    async (updated) => {
      const result = await listGoogleEventsPage({
        ...eventsRequest,
        fetch: fakeFetch(() =>
          json({
            items: [
              {
                id: "bad-updated",
                status: "confirmed",
                ...(updated === undefined ? {} : { updated }),
                start: { dateTime: "2026-03-10T13:00:00Z" },
                end: { dateTime: "2026-03-10T14:00:00Z" },
              },
            ],
          }),
        ),
      });
      expect(result).toMatchObject({ ok: false, error: { code: "invalid_response" } });
    },
  );

  it.each([
    {
      recurringEventId: "series-without-original-start",
    },
    {
      originalStartTime: { dateTime: "2026-03-10T13:00:00Z" },
    },
  ])("rejects incomplete recurrence-instance pairs", async (recurrence) => {
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      fetch: fakeFetch(() =>
        json({
          items: [
            {
              id: "bad-instance",
              status: "confirmed",
              updated: "2026-03-09T12:00:00Z",
              start: { dateTime: "2026-03-10T13:00:00Z" },
              end: { dateTime: "2026-03-10T14:00:00Z" },
              ...recurrence,
            },
          ],
        }),
      ),
    });
    expect(result).toMatchObject({ ok: false, error: { code: "invalid_response" } });
  });

  it.each([
    [{ date: "2026-03-01", dateTime: "2026-03-01T00:00:00Z" }, { date: "2026-03-02" }],
    [{ date: "2026-03-01" }, { date: "2026-03-01" }],
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
      fetch: fakeFetch(() =>
        json({
          items: [{ id: "bad", status: "confirmed", updated: "2026-03-01T00:00:00Z", start, end }],
        }),
      ),
    });
    expect(result).toEqual({
      ok: false,
      error: { code: "invalid_response", message: "Provider returned an invalid response." },
    });
  });

  it.each([{ start: { date: "2026-03-10" } }, { end: { date: "2026-03-11" } }])(
    "rejects one-sided cancelled intervals",
    async (boundaries) => {
      const result = await listGoogleEventsPage({
        ...eventsRequest,
        fetch: fakeFetch(() =>
          json({
            items: [
              {
                id: "one-sided-cancellation",
                status: "cancelled",
                updated: "2026-03-12T00:00:00Z",
                ...boundaries,
              },
            ],
          }),
        ),
      });
      expect(result).toMatchObject({ ok: false, error: { code: "invalid_response" } });
    },
  );

  it("rejects recurrence original-start kinds that conflict with a present interval", async () => {
    const result = await listGoogleEventsPage({
      ...eventsRequest,
      fetch: fakeFetch(() =>
        json({
          items: [
            {
              id: "kind-conflict",
              status: "cancelled",
              updated: "2026-03-12T00:00:00Z",
              start: { date: "2026-03-10" },
              end: { date: "2026-03-11" },
              recurringEventId: "series",
              originalStartTime: { dateTime: "2026-03-10T00:00:00Z" },
            },
          ],
        }),
      ),
    });
    expect(result).toMatchObject({ ok: false, error: { code: "invalid_response" } });
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

  it.each(["userRateLimitExceeded", "rateLimitExceeded", "quotaExceeded", "dailyLimitExceeded"])(
    "maps Calendar 403 %s usage errors to bounded rate limits",
    async (reason) => {
      const result = await listGoogleCalendarsPage({
        configuration: testConfiguration,
        accessToken: "access-secret",
        fetch: fakeFetch(() =>
          json(
            {
              error: {
                errors: [{ reason, message: "access-secret private provider detail" }],
              },
            },
            403,
            { "retry-after": "999999" },
          ),
        ),
      });
      expect(result).toEqual({
        ok: false,
        error: {
          code: "rate_limited",
          message: "Provider rate limit was reached.",
          retryAfterSeconds: 3600,
        },
      });
      expect(JSON.stringify(result)).not.toContain("access-secret");
    },
  );

  it("keeps non-usage and oversized Calendar 403 errors unauthorized", async () => {
    for (const body of [
      { error: { errors: [{ reason: "forbidden", message: "private detail" }] } },
      {
        padding: "x".repeat(16_384),
        error: { errors: [{ reason: "quotaExceeded" }] },
      },
    ]) {
      const result = await listGoogleEventsPage({
        ...eventsRequest,
        fetch: fakeFetch(() => json(body, 403, { "retry-after": "120" })),
      });
      expect(result).toEqual({
        ok: false,
        error: { code: "unauthorized", message: "Provider authorization failed." },
      });
    }
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

  it("keeps the timeout active while success, error, and revocation bodies stall", async () => {
    vi.useFakeTimers();
    try {
      const requests = [
        listGoogleCalendarsPage({
          configuration: testConfiguration,
          accessToken: "access",
          timeoutMs: 10,
          fetch: fakeFetch(() => stalledResponse(200, "application/json")),
        }),
        listGoogleEventsPage({
          ...eventsRequest,
          timeoutMs: 10,
          fetch: fakeFetch(() => stalledResponse(503, "application/json")),
        }),
        revokeGoogleTokenBestEffort({
          configuration: testConfiguration,
          token: "revocation-secret",
          timeoutMs: 10,
          fetch: fakeFetch(() => stalledResponse(200)),
        }),
      ];
      await vi.advanceTimersByTimeAsync(11);
      const results = await Promise.all(requests);
      for (const result of results) {
        expect(result).toEqual({
          ok: false,
          error: { code: "timeout", message: "Provider request timed out." },
        });
      }
    } finally {
      vi.useRealTimers();
    }
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
