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

function boundedCodePointText(maximumCharacters: number, allowEmpty = true) {
  const schema = z
    .string()
    .max(maximumCharacters * 2)
    .refine((value) => Array.from(value).length <= maximumCharacters);
  return allowEmpty ? schema : schema.refine((value) => value.length > 0);
}

export const CalendarSchema = z.strictObject({
  id: UuidSchema,
  connection_id: UuidSchema,
  name: boundedCodePointText(500, false),
  description: boundedCodePointText(4000).nullable(),
  can_write: z.boolean(),
  time_zone: boundedCodePointText(100, false).nullable(),
  is_primary: z.boolean(),
  is_selected: z.boolean(),
  color: z
    .string()
    .regex(/^#[0-9a-f]{6}$/u)
    .nullable(),
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
  time_zone: z
    .string()
    .min(1)
    .max(100)
    .refine((value) => {
      try {
        new Intl.DateTimeFormat("en", { timeZone: value });
        return true;
      } catch {
        return false;
      }
    })
    .optional(),
});

const AllDayBoundarySchema = z.strictObject({
  kind: z.literal("date"),
  date: DateSchema,
});

export const EventBoundarySchema = z.discriminatedUnion("kind", [
  TimedBoundarySchema,
  AllDayBoundarySchema,
]);

export const EventIdSchema = z.string().regex(/^e1_[A-Za-z0-9_-]{39,1403}$/u);
export const EtagSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[\x21-\x7e]+$/u);

const EventRecurrenceSchema = z.strictObject({
  series_id: EventIdSchema,
  original_start: EventBoundarySchema,
});

function eventTextSchema(maximumCharacters: number) {
  return z
    .string()
    .max(maximumCharacters * 2)
    .refine((value) => Array.from(value).length <= maximumCharacters);
}

const eventCommonShape = {
  id: EventIdSchema,
  etag: EtagSchema.nullable(),
  calendar_id: UuidSchema,
  title: eventTextSchema(1000).nullable(),
  description: eventTextSchema(16_000).nullable(),
  location: eventTextSchema(1000).nullable(),
  updated_at: Rfc3339InstantSchema.nullable(),
  recurrence: EventRecurrenceSchema.nullable(),
  transparency: z.enum(["opaque", "transparent"]),
  event_type: z.enum([
    "default",
    "focus_time",
    "out_of_office",
    "working_location",
    "birthday",
    "from_gmail",
  ]),
  self_response: z.enum(["accepted", "declined", "tentative", "needs_action"]).nullable(),
} as const;

const ConfirmedEventSchema = z.strictObject({
  ...eventCommonShape,
  updated_at: Rfc3339InstantSchema,
  etag: EtagSchema,
  status: z.literal("confirmed"),
  start: EventBoundarySchema,
  end: EventBoundarySchema,
});

const TentativeEventSchema = z.strictObject({
  ...eventCommonShape,
  updated_at: Rfc3339InstantSchema,
  etag: EtagSchema,
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
    ? left.date <= (right as z.infer<typeof AllDayBoundarySchema>).date
    : Date.parse(left.date_time) <=
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
        message: "Event boundaries must have matching kinds and not decrease.",
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
  omitted_count: z.number().int().min(0).max(250),
  next_cursor: CursorSchema.nullable(),
});

export const ChangesQuerySchema = z.strictObject({ cursor: CursorSchema.optional() });
export const ChangesResponseSchema = z
  .strictObject({
    events: z.array(EventSchema).max(250),
    omitted_count: z.number().int().min(0).max(250),
    next_cursor: CursorSchema.nullable(),
    sync_cursor: CursorSchema.nullable(),
  })
  .refine((value) => (value.next_cursor === null) !== (value.sync_cursor === null));

const RecurrenceLinesSchema = z
  .array(
    z
      .string()
      .min(1)
      .max(2048)
      .regex(/^(?:RRULE|EXDATE|RDATE)(?:;[^:\r\n]+)?:[^\r\n]+$/u),
  )
  .max(32)
  .refine((value) => new TextEncoder().encode(JSON.stringify(value)).length <= 16384);
const writeShape = {
  title: eventTextSchema(1000),
  description: eventTextSchema(16000),
  location: eventTextSchema(1000),
  start: EventBoundarySchema,
  end: EventBoundarySchema,
  transparency: z.enum(["opaque", "transparent"]),
  recurrence: RecurrenceLinesSchema,
};
export const CreateEventRequestSchema = z
  .strictObject({
    ...writeShape,
    title: writeShape.title.optional(),
    description: writeShape.description.optional(),
    location: writeShape.location.optional(),
    transparency: writeShape.transparency.optional(),
    recurrence: writeShape.recurrence.optional(),
    idempotency_key: UuidSchema,
  })
  .refine((value) => boundaryPrecedes(value.start, value.end));
export const PatchEventRequestSchema = z
  .strictObject(writeShape)
  .partial()
  .refine((value) => Object.keys(value).length > 0)
  .refine(
    (value) =>
      value.start === undefined ||
      value.end === undefined ||
      boundaryPrecedes(value.start, value.end),
  );
export type CreateEventRequest = z.infer<typeof CreateEventRequestSchema>;
export type PatchEventRequest = z.infer<typeof PatchEventRequestSchema>;
export type ChangesQuery = z.infer<typeof ChangesQuerySchema>;
export type ChangesResponse = z.infer<typeof ChangesResponseSchema>;

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
