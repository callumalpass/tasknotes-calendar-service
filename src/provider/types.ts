export type ProviderErrorCode =
  | "invalid_request"
  | "reauthorization_required"
  | "unauthorized"
  | "permission_denied"
  | "not_found"
  | "gone"
  | "duplicate"
  | "precondition"
  | "rate_limited"
  | "unavailable"
  | "timeout"
  | "network"
  | "invalid_response";

export interface ProviderError {
  readonly code: ProviderErrorCode;
  readonly message: string;
  readonly retryAfterSeconds?: number;
}

export type ProviderOutcome<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: ProviderError };

export interface ProviderPage<T> {
  readonly items: readonly T[];
  readonly nextPageToken?: string;
  readonly nextSyncToken?: string;
  readonly omittedCount?: number;
}

export interface ProviderCalendar {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly timeZone?: string;
  readonly access: "reader" | "writer" | "owner";
  readonly primary: boolean;
  /** Shown in the person's own Google Calendar. */
  readonly selected: boolean;
  /** Lower-case `#rrggbb`. */
  readonly color?: string;
}

export interface ProviderAllDayBoundary {
  readonly kind: "all_day";
  readonly date: string;
}

export interface ProviderTimedBoundary {
  readonly kind: "timed";
  readonly dateTime: string;
  readonly timeZone?: string;
}

export type ProviderEventBoundary = ProviderAllDayBoundary | ProviderTimedBoundary;

export interface ProviderEventRecurrence {
  readonly seriesId: string;
  readonly originalStart: ProviderEventBoundary;
}

export type ProviderEventType =
  "default" | "focus_time" | "out_of_office" | "working_location" | "birthday" | "from_gmail";

export type ProviderSelfResponse = "accepted" | "declined" | "tentative" | "needs_action";

interface ProviderEventCommon {
  readonly id: string;
  readonly updatedAt?: string;
  readonly etag?: string;
  readonly title?: string;
  readonly description?: string;
  readonly location?: string;
  readonly transparency: "opaque" | "transparent";
  readonly type: ProviderEventType;
  /** The signed-in person's own answer; absent when they are not an attendee. */
  readonly selfResponse?: ProviderSelfResponse;
  /** Opens the event in the provider's own web interface. */
  readonly webLink?: string;
  /** Joins the event's video conference. */
  readonly conferenceLink?: string;
  readonly recurrence?: ProviderEventRecurrence;
}

export interface ProviderScheduledEvent extends ProviderEventCommon {
  readonly updatedAt: string;
  readonly etag: string;
  readonly status: "confirmed" | "tentative";
  readonly start: ProviderEventBoundary;
  /** Google all-day end dates are preserved exactly and are exclusive. */
  readonly end: ProviderEventBoundary;
}

interface ProviderCancelledEventWithoutInterval extends ProviderEventCommon {
  readonly status: "cancelled";
  readonly start?: never;
  readonly end?: never;
}

interface ProviderCancelledEventWithInterval extends ProviderEventCommon {
  readonly status: "cancelled";
  readonly start: ProviderEventBoundary;
  /** Google all-day end dates are preserved exactly and are exclusive. */
  readonly end: ProviderEventBoundary;
}

/** Google tombstones have either a complete interval or no interval. */
export type ProviderCancelledEvent =
  ProviderCancelledEventWithoutInterval | ProviderCancelledEventWithInterval;

export type ProviderEvent = ProviderScheduledEvent | ProviderCancelledEvent;
