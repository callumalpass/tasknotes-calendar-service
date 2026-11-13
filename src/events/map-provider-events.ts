import type { CalendarEvent, EventBoundary } from "../contracts";
import { sealEventId, type EventIdBinding } from "../crypto/event-id";
import type { ProviderEvent, ProviderEventBoundary } from "../provider/types";

export interface ProviderEventMappingContext extends EventIdBinding {
  readonly eventIdKey: Uint8Array;
}

export class EventMappingError extends Error {
  public constructor() {
    super("Provider event mapping failed");
    this.name = "EventMappingError";
  }
}

function publicBoundary(boundary: ProviderEventBoundary): EventBoundary {
  return boundary.kind === "all_day"
    ? { kind: "date", date: boundary.date }
    : {
        kind: "date_time",
        date_time: boundary.dateTime,
        ...(boundary.timeZone === undefined ? {} : { time_zone: boundary.timeZone }),
      };
}

export async function mapProviderEvents(
  events: readonly ProviderEvent[],
  context: ProviderEventMappingContext,
): Promise<readonly CalendarEvent[]> {
  try {
    return await Promise.all(
      events.map(async (event) => {
        const common = {
          id: await sealEventId(event.id, context, context.eventIdKey),
          calendar_id: context.authorizationScopedCalendarId,
          etag: event.etag ?? null,
          title: event.title ?? null,
          description: event.description ?? null,
          location: event.location ?? null,
          updated_at: event.updatedAt ?? null,
          transparency: event.transparency,
          event_type: event.type,
          self_response: event.selfResponse ?? null,
          web_link: event.webLink ?? null,
          conference_link: event.conferenceLink ?? null,
          recurrence:
            event.recurrence === undefined
              ? null
              : {
                  series_id: await sealEventId(
                    event.recurrence.seriesId,
                    context,
                    context.eventIdKey,
                  ),
                  original_start: publicBoundary(event.recurrence.originalStart),
                },
        };
        return event.status === "cancelled"
          ? {
              ...common,
              status: event.status,
              start: event.start === undefined ? null : publicBoundary(event.start),
              end: event.end === undefined ? null : publicBoundary(event.end),
            }
          : {
              ...common,
              updated_at: event.updatedAt,
              etag: event.etag,
              status: event.status,
              start: publicBoundary(event.start),
              end: publicBoundary(event.end),
            };
      }),
    );
  } catch {
    throw new EventMappingError();
  }
}
