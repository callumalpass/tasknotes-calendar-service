import { z } from "zod";

import { EventSchema, UuidSchema, type CalendarEvent, type EventBoundary } from "../contracts";
import type { ProviderEvent } from "../provider/types";

const encoder = new TextEncoder();
const EVENT_ID_PURPOSE = "tasknotes-public-event-id";
const EVENT_ID_VERSION = 1;

const boundedProviderString = (maximumBytes: number, allowEmpty = false) =>
  z
    .string()
    .refine((value) => allowEmpty || value.length > 0)
    .refine((value) => encoder.encode(value).byteLength <= maximumBytes);

const providerTimedBoundarySchema = z.strictObject({
  kind: z.literal("timed"),
  dateTime: z.iso.datetime({ offset: true }),
  timeZone: boundedProviderString(256).optional(),
});
const providerAllDayBoundarySchema = z.strictObject({
  kind: z.literal("all_day"),
  date: z.iso.date(),
});
const providerBoundarySchema = z.discriminatedUnion("kind", [
  providerTimedBoundarySchema,
  providerAllDayBoundarySchema,
]);
const providerRecurrenceSchema = z.strictObject({
  seriesId: boundedProviderString(4096),
  originalStart: providerBoundarySchema,
});
const providerCommonShape = {
  id: boundedProviderString(4096),
  updatedAt: z.iso.datetime({ offset: true }),
  title: boundedProviderString(2048, true).optional(),
  description: boundedProviderString(32_768, true).optional(),
  location: boundedProviderString(8192, true).optional(),
  transparency: z.enum(["opaque", "transparent"]),
  recurrence: providerRecurrenceSchema.optional(),
} as const;
const providerScheduledSchema = z.union([
  z.strictObject({
    ...providerCommonShape,
    status: z.literal("confirmed"),
    start: providerBoundarySchema,
    end: providerBoundarySchema,
  }),
  z.strictObject({
    ...providerCommonShape,
    status: z.literal("tentative"),
    start: providerBoundarySchema,
    end: providerBoundarySchema,
  }),
]);
const providerCancelledSchema = z.union([
  z.strictObject({ ...providerCommonShape, status: z.literal("cancelled") }),
  z.strictObject({
    ...providerCommonShape,
    status: z.literal("cancelled"),
    start: providerBoundarySchema,
    end: providerBoundarySchema,
  }),
]);
const providerEventSchema = z
  .union([providerScheduledSchema, providerCancelledSchema])
  .superRefine((event, context) => {
    const boundaries = [
      ...(event.recurrence === undefined ? [] : [event.recurrence.originalStart]),
      ...("start" in event ? [event.start] : []),
      ...("end" in event ? [event.end] : []),
    ];
    if (boundaries.some((boundary) => !providerBoundaryHasValidZone(boundary))) {
      context.addIssue({ code: "custom", message: "invalid provider boundary" });
      return;
    }
    if (!("start" in event) || !("end" in event)) return;
    if (!providerBoundaryPrecedes(event.start, event.end)) {
      context.addIssue({ code: "custom", message: "invalid provider interval" });
      return;
    }
    if (
      event.recurrence?.originalStart.kind !== undefined &&
      event.recurrence.originalStart.kind !== event.start.kind
    ) {
      context.addIssue({ code: "custom", message: "invalid provider recurrence" });
    }
  });

const mappingContextSchema = z.strictObject({
  environment: z.enum(["local", "lab", "staging", "production"]),
  provider: z.literal("google"),
  authorizationScopedCalendarId: UuidSchema,
  eventIdKey: z.instanceof(Uint8Array).refine((key) => key.byteLength === 32),
});

/**
 * The calendar UUID must be resolved by the caller under the authenticated principal's authority.
 * It is both emitted publicly and bound into every deterministic event identifier.
 */
export interface ProviderEventMappingContext {
  readonly environment: "local" | "lab" | "staging" | "production";
  readonly provider: "google";
  readonly authorizationScopedCalendarId: string;
  readonly eventIdKey: Uint8Array;
}

export class EventMappingError extends Error {
  public constructor() {
    super("Provider event mapping failed");
    this.name = "EventMappingError";
  }
}

function providerBoundaryHasValidZone(boundary: z.infer<typeof providerBoundarySchema>): boolean {
  if (boundary.kind === "all_day" || boundary.timeZone === undefined) return true;
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: boundary.timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    }).formatToParts(new Date(boundary.dateTime));
    const values = new Map(parts.map((part) => [part.type, part.value]));
    return (
      `${values.get("year")}-${values.get("month")}-${values.get("day")}T${values.get("hour")}:${values.get("minute")}:${values.get("second")}` ===
      boundary.dateTime.slice(0, 19)
    );
  } catch {
    return false;
  }
}

function providerBoundaryPrecedes(
  left: z.infer<typeof providerBoundarySchema>,
  right: z.infer<typeof providerBoundarySchema>,
): boolean {
  if (left.kind !== right.kind) return false;
  return left.kind === "all_day"
    ? left.date < (right as z.infer<typeof providerAllDayBoundarySchema>).date
    : Date.parse(left.dateTime) <
        Date.parse((right as z.infer<typeof providerTimedBoundarySchema>).dateTime);
}

function publicBoundary(boundary: z.infer<typeof providerBoundarySchema>): EventBoundary {
  return boundary.kind === "all_day"
    ? { kind: "date", date: boundary.date }
    : {
        kind: "date_time",
        date_time: boundary.dateTime,
        ...(boundary.timeZone === undefined ? {} : { time_zone: boundary.timeZone }),
      };
}

function formatUuid(bytes: Uint8Array): string {
  const hexadecimal = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hexadecimal.slice(0, 8)}-${hexadecimal.slice(8, 12)}-${hexadecimal.slice(12, 16)}-${hexadecimal.slice(16, 20)}-${hexadecimal.slice(20)}`;
}

async function deriveEventUuid(
  key: CryptoKey,
  context: Omit<ProviderEventMappingContext, "eventIdKey">,
  providerEventId: string,
): Promise<string> {
  const tuple = JSON.stringify([
    EVENT_ID_PURPOSE,
    EVENT_ID_VERSION,
    context.environment,
    context.provider,
    context.authorizationScopedCalendarId,
    providerEventId,
  ]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(tuple))).slice(
    0,
    16,
  );
  digest[6] = ((digest[6] ?? 0) & 0x0f) | 0x80;
  digest[8] = ((digest[8] ?? 0) & 0x3f) | 0x80;
  return formatUuid(digest);
}

/** Maps one already-bounded provider page without storage, caching, or D1 access. */
export async function mapProviderEvents(
  events: readonly ProviderEvent[],
  suppliedContext: ProviderEventMappingContext,
): Promise<readonly CalendarEvent[]> {
  try {
    const parsedContext = mappingContextSchema.parse(suppliedContext);
    const key = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(parsedContext.eventIdKey).buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const context = {
      environment: parsedContext.environment,
      provider: parsedContext.provider,
      authorizationScopedCalendarId: parsedContext.authorizationScopedCalendarId,
    } as const;

    return await Promise.all(
      events.map(async (suppliedEvent) => {
        const event = providerEventSchema.parse(suppliedEvent);
        const recurrence =
          event.recurrence === undefined
            ? null
            : {
                series_id: await deriveEventUuid(key, context, event.recurrence.seriesId),
                original_start: publicBoundary(event.recurrence.originalStart),
              };
        const common = {
          id: await deriveEventUuid(key, context, event.id),
          calendar_id: context.authorizationScopedCalendarId,
          title: event.title ?? null,
          description: event.description ?? null,
          location: event.location ?? null,
          updated_at: event.updatedAt,
          recurrence,
        } as const;
        const mapped =
          event.status === "cancelled"
            ? {
                ...common,
                status: event.status,
                start: "start" in event ? publicBoundary(event.start) : null,
                end: "end" in event ? publicBoundary(event.end) : null,
              }
            : {
                ...common,
                status: event.status,
                start: publicBoundary(event.start),
                end: publicBoundary(event.end),
              };
        return EventSchema.parse(mapped);
      }),
    );
  } catch {
    throw new EventMappingError();
  }
}
