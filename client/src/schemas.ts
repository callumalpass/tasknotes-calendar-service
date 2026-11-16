// The subpath is the one entry point both zod 3.25 and zod 4 provide. The namespace import lets
// bundlers drop the zod exports this package does not use; `import { z }` keeps all of them,
// locales included.
import * as z from "zod/v4";

export const id = z.uuid();
export const eventId = z.string().regex(/^e1_[A-Za-z0-9_-]+$/);

export const calendarSchema = z.object({
  id,
  name: z.string(),
  can_write: z.boolean(),
  is_primary: z.boolean(),
  // A calendar service older than its ADR 0007 sends neither of these.
  is_selected: z.boolean().optional(),
  color: z.string().nullable().optional(),
});

export const connectionSchema = z.object({
  id,
  status: z.enum(["active", "reconnect_required"]),
});

const boundarySchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("date"), date: z.iso.date() }),
  z.object({
    kind: z.literal("date_time"),
    date_time: z.iso.datetime({ offset: true }),
    time_zone: z.string().optional(),
  }),
]);

export const eventSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("cancelled"), id: eventId }),
  z.object({
    status: z.enum(["confirmed", "tentative"]),
    id: eventId,
    etag: z.string().min(1),
    calendar_id: id,
    title: z.string().nullable(),
    description: z.string().nullable(),
    location: z.string().nullable(),
    recurrence: z.object({ series_id: eventId }).nullable(),
    // Absent from an older service. Kept as text so a kind or an answer the
    // service adds later cannot fail a page.
    event_type: z.string().optional(),
    self_response: z.string().nullable().optional(),
    transparency: z.string().optional(),
    web_link: z.string().nullable().optional(),
    conference_link: z.string().nullable().optional(),
    start: boundarySchema,
    end: boundarySchema,
  }),
]);

export const scheduledEventSchema = eventSchema.transform((event, context) => {
  if (event.status !== "cancelled") return event;
  context.addIssue({ code: "custom", message: "Event is cancelled." });
  return z.NEVER;
});

export const pageSchema = z.object({
  events: z.array(eventSchema),
  omitted_count: z.number().int().min(0),
  next_cursor: z.string().min(1).nullable(),
});

export const startSchema = z.object({
  transaction_id: z.string().min(1),
  polling_secret: z.string().min(1),
  authorization_url: z.url(),
  expires_at: z.iso.datetime({ offset: true }),
});

export const statusSchema = z.object({
  status: z.enum(["pending", "authorized", "failed", "expired"]),
});

/** A web session: the credential travels only in the service's cookie. */
export const sessionSchema = z.object({
  session: z.object({
    session_id: z.string().min(1),
  }),
});

/** Every other client is handed its bearer credential once, on redeeming. */
export const bearerSessionSchema: z.ZodType<{
  session: { session_id: string; credential?: string };
}> = z.object({
  session: z.object({
    session_id: z.string().min(1),
    credential: z.string().min(1),
  }),
});

export const currentSessionSchema = z.object({ session_id: z.string().min(1) });
export const errorSchema = z.object({ code: z.string() });

export type GoogleCalendar = z.infer<typeof calendarSchema>;
export type GoogleConnection = z.infer<typeof connectionSchema>;
export type EventBoundary = z.infer<typeof boundarySchema>;
export type GoogleEvent = Exclude<z.infer<typeof eventSchema>, { status: "cancelled" }>;
export type EventPage = z.infer<typeof pageSchema>;

export interface EventFields {
  title?: string;
  description?: string;
  location?: string;
  start?: EventBoundary;
  end?: EventBoundary;
}

export const redeemedConnectionSchema = z.object({ connection_id: id });
export const connectionsSchema = z.object({ connections: z.array(connectionSchema).max(1) });
export const calendarsSchema = z.object({ calendars: z.array(calendarSchema) });
export const selectionSchema = z.array(id);
