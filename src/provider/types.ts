export type ProviderErrorCode =
  | "invalid_request"
  | "unauthorized"
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

interface ProviderEventCommon {
  readonly id: string;
  readonly title?: string;
  readonly description?: string;
  readonly location?: string;
  readonly transparency: "opaque" | "transparent";
  readonly recurringEventId?: string;
  readonly originalStart?: ProviderEventBoundary;
}

export interface ProviderScheduledEvent extends ProviderEventCommon {
  readonly status: "confirmed" | "tentative";
  readonly start: ProviderEventBoundary;
  /** Google all-day ends are preserved as exclusive dates. */
  readonly end: ProviderEventBoundary;
}

export interface ProviderCancelledEvent extends ProviderEventCommon {
  readonly status: "cancelled";
  /** Cancelled recurrence exceptions may contain only their original start. */
  readonly start?: ProviderEventBoundary;
  readonly end?: ProviderEventBoundary;
}

export type ProviderEvent = ProviderScheduledEvent | ProviderCancelledEvent;
