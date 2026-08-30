import { describe, expect, it } from "vitest";

import {
  EventSchema,
  EventsQuerySchema,
  ProviderCallbackQuerySchema,
  TransactionStartRequestSchema,
} from "../../../src/contracts";

const id = "550e8400-e29b-41d4-a716-446655440000";

function timedEvent() {
  return {
    id,
    calendar_id: id,
    status: "confirmed",
    title: "Planning",
    description: null,
    location: null,
    start: { kind: "date_time", date_time: "2026-09-01T10:00:00Z" },
    end: { kind: "date_time", date_time: "2026-09-01T11:00:00Z" },
    updated_at: "2026-08-30T12:00:00Z",
    recurrence: null,
  };
}

describe("public contract schemas", () => {
  it("accepts only the four first-slice clients and a strict start body", () => {
    const valid = {
      client_kind: "obsidian",
      device_name: "Work laptop",
      code_challenge: "A".repeat(43),
    };
    expect(TransactionStartRequestSchema.safeParse(valid).success).toBe(true);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, code_challenge: "a".repeat(44) }).success,
    ).toBe(false);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, client_kind: "desktop" }).success,
    ).toBe(false);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, provider: "microsoft" }).success,
    ).toBe(false);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, device_name: " ".repeat(81) }).success,
    ).toBe(false);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, device_name: "😀".repeat(32) }).success,
    ).toBe(true);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, device_name: "😀".repeat(33) }).success,
    ).toBe(false);
    expect(
      TransactionStartRequestSchema.safeParse({ ...valid, device_name: "Work\u0000laptop" })
        .success,
    ).toBe(false);
  });

  it("requires RFC3339 instants, increasing ranges, and at most 93 days", () => {
    expect(
      EventsQuerySchema.safeParse({ start: "2026-01-01T00:00:00Z", end: "2026-04-04T00:00:00Z" })
        .success,
    ).toBe(true);
    expect(
      EventsQuerySchema.safeParse({
        start: "2026-01-01T00:00:00Z",
        end: "2026-04-04T00:00:00.001Z",
      }).success,
    ).toBe(false);
    expect(
      EventsQuerySchema.safeParse({ start: "2026-01-01T00:00:00", end: "2026-01-02T00:00:00Z" })
        .success,
    ).toBe(false);
    expect(
      EventsQuerySchema.safeParse({ start: "2026-01-02T00:00:00Z", end: "2026-01-01T00:00:00Z" })
        .success,
    ).toBe(false);
  });

  it("bounds opaque cursors and rejects unknown query keys", () => {
    const range = { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" };
    expect(EventsQuerySchema.safeParse({ ...range, cursor: "c".repeat(16) }).success).toBe(true);
    expect(EventsQuerySchema.safeParse({ ...range, cursor: "short" }).success).toBe(false);
    expect(EventsQuerySchema.safeParse({ ...range, cursor: "c".repeat(2049) }).success).toBe(false);
    expect(EventsQuerySchema.safeParse({ ...range, calendar_id: id }).success).toBe(false);
  });

  it("enforces strict scheduled variants, ordered matching boundaries, and recurrence", () => {
    expect(EventSchema.safeParse(timedEvent()).success).toBe(true);
    expect(EventSchema.safeParse({ ...timedEvent(), title: "😀".repeat(1000) }).success).toBe(true);
    expect(EventSchema.safeParse({ ...timedEvent(), title: "😀".repeat(1001) }).success).toBe(
      false,
    );
    for (const event of [
      { ...timedEvent(), end: { kind: "date", date: "2026-09-02" } },
      { ...timedEvent(), end: timedEvent().start },
      { ...timedEvent(), start: timedEvent().end, end: timedEvent().start },
      { ...timedEvent(), attendees: [] },
      { ...timedEvent(), recurrence: undefined },
      {
        ...timedEvent(),
        recurrence: { series_id: id, original_start: { kind: "date", date: "2026-09-01" } },
      },
      {
        ...timedEvent(),
        recurrence: { series_id: id, original_start: timedEvent().start, extra: true },
      },
    ]) {
      expect(EventSchema.safeParse(event).success).toBe(false);
    }
  });

  it("requires cancelled boundary pairs and validates every present interval", () => {
    const tombstone = { ...timedEvent(), status: "cancelled", start: null, end: null };
    expect(EventSchema.safeParse(tombstone).success).toBe(true);
    expect(EventSchema.safeParse({ ...tombstone, start: timedEvent().start }).success).toBe(false);
    expect(EventSchema.safeParse({ ...tombstone, end: timedEvent().end }).success).toBe(false);
    expect(
      EventSchema.safeParse({
        ...tombstone,
        start: timedEvent().end,
        end: timedEvent().start,
      }).success,
    ).toBe(false);
    expect(
      EventSchema.safeParse({
        ...tombstone,
        start: { kind: "date", date: "2024-02-29" },
        end: { kind: "date", date: "2024-03-01" },
      }).success,
    ).toBe(true);
  });

  it("accepts exactly a provider success or bounded provider error callback", () => {
    const state = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8";
    expect(
      ProviderCallbackQuerySchema.safeParse({
        code: "c".repeat(32),
        state,
        scope: "openid email profile",
        authuser: "0",
        prompt: "consent",
        iss: "https://accounts.google.com",
      }).success,
    ).toBe(true);
    expect(
      ProviderCallbackQuerySchema.safeParse({
        error: "provider_specific_error",
        error_description: "Authorization failed",
        state,
      }).success,
    ).toBe(true);
    expect(
      ProviderCallbackQuerySchema.safeParse({ code: "c".repeat(32), error: "access_denied", state })
        .success,
    ).toBe(false);
    expect(
      ProviderCallbackQuerySchema.safeParse({ code: "c".repeat(32), state, unrelated: "x" })
        .success,
    ).toBe(false);
  });
});
