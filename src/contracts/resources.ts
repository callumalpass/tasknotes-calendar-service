import { z } from "zod";

import {
  ClientKindSchema,
  CursorSchema,
  DateSchema,
  DeviceNameSchema,
  DeviceSessionIdSchema,
  isBoundedEventRange,
  Rfc3339InstantSchema,
  UuidSchema,
} from "./common";

export const SessionSchema = z.strictObject({
  principal_id: UuidSchema,
  session_id: DeviceSessionIdSchema,
  client_kind: ClientKindSchema,
  device_name: DeviceNameSchema,
  created_at: Rfc3339InstantSchema,
  idle_expires_at: Rfc3339InstantSchema,
  absolute_expires_at: Rfc3339InstantSchema,
});

export const ConnectionSchema = z.strictObject({
  id: UuidSchema,
  provider: z.literal("google"),
  status: z.enum(["active", "reconnect_required"]),
  created_at: Rfc3339InstantSchema,
  updated_at: Rfc3339InstantSchema,
});

export const ConnectionsResponseSchema = z.strictObject({
  connections: z.array(ConnectionSchema).max(1),
});

export const CalendarSchema = z.strictObject({
  id: UuidSchema,
  connection_id: UuidSchema,
  name: z.string().min(1).max(500),
  description: z.string().max(4000).nullable(),
  color: z.string().max(32).nullable(),
  time_zone: z.string().min(1).max(100).nullable(),
  is_primary: z.boolean(),
});

export const CalendarsResponseSchema = z.strictObject({
  calendars: z.array(CalendarSchema).max(250),
});

export const EventsQuerySchema = z
  .strictObject({
    start: Rfc3339InstantSchema,
    end: Rfc3339InstantSchema,
    cursor: CursorSchema.optional(),
  })
  .refine(({ start, end }) => isBoundedEventRange(start, end), {
    message: "Event range must increase and span no more than 93 days.",
  });

const TimedBoundarySchema = z.strictObject({
  kind: z.literal("date_time"),
  date_time: Rfc3339InstantSchema,
  time_zone: z.string().min(1).max(100).optional(),
});

const AllDayBoundarySchema = z.strictObject({
  kind: z.literal("date"),
  date: DateSchema,
});

export const EventBoundarySchema = z.discriminatedUnion("kind", [
  TimedBoundarySchema,
  AllDayBoundarySchema,
]);

const EventRecurrenceSchema = z.strictObject({
  series_id: UuidSchema,
  original_start: EventBoundarySchema,
});

function eventTextSchema(maximumCharacters: number) {
  return z
    .string()
    .max(maximumCharacters * 2)
    .refine((value) => Array.from(value).length <= maximumCharacters);
}

const eventCommonShape = {
  id: UuidSchema,
  calendar_id: UuidSchema,
  title: eventTextSchema(1000).nullable(),
  description: eventTextSchema(16_000).nullable(),
  location: eventTextSchema(1000).nullable(),
  updated_at: Rfc3339InstantSchema,
  recurrence: EventRecurrenceSchema.nullable(),
} as const;

const ConfirmedEventSchema = z.strictObject({
  ...eventCommonShape,
  status: z.literal("confirmed"),
  start: EventBoundarySchema,
  end: EventBoundarySchema,
});

const TentativeEventSchema = z.strictObject({
  ...eventCommonShape,
  status: z.literal("tentative"),
  start: EventBoundarySchema,
  end: EventBoundarySchema,
});

const CancelledEventSchema = z.strictObject({
  ...eventCommonShape,
  status: z.literal("cancelled"),
  start: EventBoundarySchema.nullable(),
  end: EventBoundarySchema.nullable(),
});

function boundaryPrecedes(
  left: z.infer<typeof EventBoundarySchema>,
  right: z.infer<typeof EventBoundarySchema>,
): boolean {
  if (left.kind !== right.kind) return false;
  return left.kind === "date"
    ? left.date < (right as z.infer<typeof AllDayBoundarySchema>).date
    : Date.parse(left.date_time) <
        Date.parse((right as z.infer<typeof TimedBoundarySchema>).date_time);
}

export const EventSchema = z
  .discriminatedUnion("status", [ConfirmedEventSchema, TentativeEventSchema, CancelledEventSchema])
  .superRefine((event, context) => {
    if ((event.start === null) !== (event.end === null)) {
      context.addIssue({ code: "custom", message: "Cancelled boundaries must both be null." });
      return;
    }
    if (event.start === null || event.end === null) return;
    if (!boundaryPrecedes(event.start, event.end)) {
      context.addIssue({
        code: "custom",
        message: "Event boundaries must have matching kinds and increase strictly.",
      });
      return;
    }
    if (
      event.status !== "cancelled" &&
      event.recurrence !== null &&
      event.recurrence.original_start.kind !== event.start.kind
    ) {
      context.addIssue({
        code: "custom",
        message: "Scheduled recurrence must use the event boundary kind.",
      });
    }
  });

export const EventsResponseSchema = z.strictObject({
  events: z.array(EventSchema).max(250),
  next_cursor: CursorSchema.nullable(),
});

export const DeviceSchema = z.strictObject({
  id: DeviceSessionIdSchema,
  client_kind: ClientKindSchema,
  device_name: DeviceNameSchema,
  created_at: Rfc3339InstantSchema,
  last_used_at: Rfc3339InstantSchema,
  current: z.boolean(),
});

export const DevicesResponseSchema = z.strictObject({ devices: z.array(DeviceSchema).max(100) });

export type Session = z.infer<typeof SessionSchema>;
export type Connection = z.infer<typeof ConnectionSchema>;
export type ConnectionsResponse = z.infer<typeof ConnectionsResponseSchema>;
export type Calendar = z.infer<typeof CalendarSchema>;
export type CalendarsResponse = z.infer<typeof CalendarsResponseSchema>;
export type EventsQuery = z.infer<typeof EventsQuerySchema>;
export type EventBoundary = z.infer<typeof EventBoundarySchema>;
export type CalendarEvent = z.infer<typeof EventSchema>;
export type EventsResponse = z.infer<typeof EventsResponseSchema>;
export type Device = z.infer<typeof DeviceSchema>;
export type DevicesResponse = z.infer<typeof DevicesResponseSchema>;
