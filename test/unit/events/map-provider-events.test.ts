import { describe, expect, it } from "vitest";

import {
  EventMappingError,
  mapProviderEvents,
  type ProviderEventMappingContext,
} from "../../../src/events/map-provider-events";
import type { ProviderEvent } from "../../../src/provider/types";

const CALENDAR_ID = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_CALENDAR_ID = "123e4567-e89b-42d3-a456-426614174000";
const KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
const context = {
  environment: "local",
  provider: "google",
  authorizationScopedCalendarId: CALENDAR_ID,
  eventIdKey: KEY,
} as const satisfies ProviderEventMappingContext;

function event(overrides: Partial<ProviderEvent> = {}): ProviderEvent {
  return {
    id: "provider-event\u0000|:id",
    status: "confirmed",
    updatedAt: "2026-08-30T12:00:00Z",
    title: "Planning",
    transparency: "opaque",
    start: { kind: "timed", dateTime: "2026-09-01T10:00:00Z" },
    end: { kind: "timed", dateTime: "2026-09-01T11:00:00Z" },
    ...overrides,
  };
}

async function mappedId(
  overrides: Partial<ProviderEvent> = {},
  contextOverrides: Partial<ProviderEventMappingContext> = {},
): Promise<string> {
  const [mapped] = await mapProviderEvents([event(overrides)], { ...context, ...contextOverrides });
  if (mapped === undefined) throw new Error("expected mapped event");
  return mapped.id;
}

describe("provider event public mapping", () => {
  it("matches a fixed UUIDv8 vector and maps the canonical projection", async () => {
    const [mapped] = await mapProviderEvents([event()], context);
    expect(mapped).toEqual({
      id: "93d45468-3efe-87dd-83a7-835dd49d6fa2",
      calendar_id: CALENDAR_ID,
      status: "confirmed",
      title: "Planning",
      description: null,
      location: null,
      start: { kind: "date_time", date_time: "2026-09-01T10:00:00Z" },
      end: { kind: "date_time", date_time: "2026-09-01T11:00:00Z" },
      updated_at: "2026-08-30T12:00:00Z",
      recurrence: null,
    });
  });

  it("is stable under repetition and concurrent mapping with valid UUID version and variant", async () => {
    const ids = await Promise.all(Array.from({ length: 40 }, async () => mappedId()));
    expect(new Set(ids)).toEqual(new Set([ids[0]]));
    for (const id of ids) {
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    }
  });

  it("separates environment, authorization-scoped calendar, and dedicated key", async () => {
    const base = await mappedId();
    const separated = await Promise.all([
      mappedId({}, { environment: "lab" }),
      mappedId({}, { authorizationScopedCalendarId: OTHER_CALENDAR_ID }),
      mappedId({}, { eventIdKey: new Uint8Array(32).fill(9) }),
    ]);
    expect(new Set([base, ...separated])).toHaveLength(4);
  });

  it("uses unambiguous structured inputs for delimiter and control-character provider IDs", async () => {
    const ids = await Promise.all(
      ["a|b:c", "a|b\u0000c", "a", "a\u0000", '["a","b"]'].map(async (id) => mappedId({ id })),
    );
    expect(new Set(ids)).toHaveLength(ids.length);
  });

  it("derives recurrence IDs consistently and preserves leap-day exclusive ends", async () => {
    const providerId = "same-provider-material";
    const [mapped] = await mapProviderEvents(
      [
        event({
          id: providerId,
          status: "tentative",
          start: { kind: "all_day", date: "2024-02-29" },
          end: { kind: "all_day", date: "2024-03-02" },
          recurrence: {
            seriesId: providerId,
            originalStart: { kind: "all_day", date: "2024-02-29" },
          },
        }),
      ],
      context,
    );
    expect(mapped?.id).toBe(mapped?.recurrence?.series_id);
    expect(mapped).toMatchObject({
      start: { kind: "date", date: "2024-02-29" },
      end: { kind: "date", date: "2024-03-02" },
      recurrence: { original_start: { kind: "date", date: "2024-02-29" } },
    });
  });

  it("normalizes absent text and recurrence to null and emits complete null tombstones", async () => {
    const providerId = "private-cancelled-provider-id";
    const [mapped] = await mapProviderEvents(
      [
        {
          id: providerId,
          status: "cancelled",
          updatedAt: "2026-08-30T12:00:00Z",
          transparency: "opaque",
        },
      ],
      context,
    );
    expect(mapped).toMatchObject({
      status: "cancelled",
      title: null,
      description: null,
      location: null,
      start: null,
      end: null,
      recurrence: null,
    });
    expect(JSON.stringify(mapped)).not.toContain(providerId);
  });

  it.each([
    { authorizationScopedCalendarId: "not-a-uuid" },
    { environment: "test" },
    { provider: "microsoft" },
    { eventIdKey: new Uint8Array(31) },
  ])(
    "fails generically for malformed context without exposing supplied values",
    async (invalid) => {
      const supplied = { ...context, ...invalid } as unknown as ProviderEventMappingContext;
      const rejection = mapProviderEvents([event()], supplied);
      await expect(rejection).rejects.toBeInstanceOf(EventMappingError);
      await rejection.catch((error: unknown) => {
        expect(String(error)).toBe("EventMappingError: Provider event mapping failed");
        expect(String(error)).not.toContain(String(Object.values(invalid)[0]));
      });
    },
  );

  it.each([
    { updatedAt: "malformed" },
    { id: "" },
    { extra: "raw" },
    { end: { kind: "timed", dateTime: "2026-09-01T10:00:00Z" } },
    { end: { kind: "all_day", date: "2026-09-02" } },
    {
      start: {
        kind: "timed",
        dateTime: "2026-09-01T10:00:00Z",
        timeZone: "America/New_York",
      },
    },
    { title: "x".repeat(1001) },
    {
      recurrence: {
        seriesId: "series",
        originalStart: { kind: "all_day", date: "2026-09-01" },
      },
    },
  ])("fails generically for malformed private domain values", async (invalid) => {
    const raw = { ...event(), ...invalid } as unknown as ProviderEvent;
    await expect(mapProviderEvents([raw], context)).rejects.toEqual(new EventMappingError());
  });
});
