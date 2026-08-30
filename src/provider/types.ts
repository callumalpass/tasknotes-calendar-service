export type ProviderErrorCode =
  | "invalid_request"
  | "reauthorization_required"
  | "unauthorized"
  | "permission_denied"
  | "not_found"
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
}

export interface ProviderCalendar {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly timeZone?: string;
  readonly access: "reader" | "writer" | "owner";
  readonly primary: boolean;
  readonly selected: boolean;
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

interface ProviderEventCommon {
  readonly id: string;
  readonly updatedAt: string;
  readonly title?: string;
  readonly description?: string;
  readonly location?: string;
  readonly transparency: "opaque" | "transparent";
  readonly recurrence?: ProviderEventRecurrence;
}

export interface ProviderScheduledEvent extends ProviderEventCommon {
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
