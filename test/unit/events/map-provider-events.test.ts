import { describe, expect, it } from "vitest";

import {
  EventMappingError,
  mapProviderEvents,
  type ProviderEventMappingContext,
} from "../../../src/events/map-provider-events";
import { openEventId } from "../../../src/crypto/event-id";
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
    etag: '"1"',
    title: "Planning",
    transparency: "opaque",
    type: "default",
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
  it("emits a deterministic sealed identifier and maps the canonical projection", async () => {
    const [mapped] = await mapProviderEvents([event()], context);
    expect(mapped).toEqual({
      id: await mappedId(),
      etag: '"1"',
      calendar_id: CALENDAR_ID,
      status: "confirmed",
      title: "Planning",
      description: null,
      location: null,
      start: { kind: "date_time", date_time: "2026-09-01T10:00:00Z" },
      end: { kind: "date_time", date_time: "2026-09-01T11:00:00Z" },
      updated_at: "2026-08-30T12:00:00Z",
      recurrence: null,
      transparency: "opaque",
      event_type: "default",
      self_response: null,
    });
  });

  it("carries availability, the kind of entry and the person's own answer", async () => {
    const [mapped] = await mapProviderEvents(
      [event({ transparency: "transparent", type: "working_location", selfResponse: "declined" })],
      context,
    );
    expect(mapped).toMatchObject({
      transparency: "transparent",
      event_type: "working_location",
      self_response: "declined",
    });
  });

  it("is stable under repetition and concurrent mapping with reversible opaque IDs", async () => {
    const ids = await Promise.all(Array.from({ length: 40 }, async () => mappedId()));
    expect(new Set(ids)).toEqual(new Set([ids[0]]));
    for (const id of ids) {
      expect(id).toMatch(/^e1_[A-Za-z0-9_-]+$/u);
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
          type: "default",
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
      self_response: null,
    });
    expect(JSON.stringify(mapped)).not.toContain(providerId);
  });

  it("opens only under the original calendar and key", async () => {
    const id = await mappedId();
    await expect(openEventId(id, context, KEY)).resolves.toBe(event().id);
    await expect(
      openEventId(id, { ...context, authorizationScopedCalendarId: OTHER_CALENDAR_ID }, KEY),
    ).rejects.toThrow();
    await expect(openEventId(id, context, new Uint8Array(32).fill(9))).rejects.toThrow();
  });
  it("fails generically for invalid key material or an oversized provider ID", async () => {
    await expect(
      mapProviderEvents([event()], { ...context, eventIdKey: new Uint8Array(31) }),
    ).rejects.toEqual(new EventMappingError());
    await expect(mapProviderEvents([event({ id: "x".repeat(1025) })], context)).rejects.toEqual(
      new EventMappingError(),
    );
  });
});
