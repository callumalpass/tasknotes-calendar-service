export const FAKE_GOOGLE_ORIGIN = "http://127.0.0.1:9797";
export const FAKE_GOOGLE_CLIENT_ID = "local-fake-google-client";
export const FAKE_GOOGLE_CLIENT_SECRET = "test-only-fake-google-secret";
export const FAKE_GOOGLE_REDIRECT_URI = "http://127.0.0.1:8787/oauth/google/callback";
export const FAKE_GOOGLE_KID = "test-only-fake-google-rs256-1";
export const FAKE_CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";

export type FakeTokenMode =
  | "success"
  | "wrong_nonce"
  | "wrong_issuer"
  | "alternate_issuer"
  | "wrong_audience"
  | "wrong_azp"
  | "wrong_signature"
  | "expired"
  | "omitted_scope"
  | "writable_scope"
  | "missing_refresh_token"
  | "rate_limited"
  | "stall"
  | "consume_then_fail";

export type FakeRefreshMode =
  | "success"
  | "rotate"
  | "omit_refresh"
  | "omit_scope"
  | "invalid_grant"
  | "writable_scope"
  | "unknown_scope"
  | "rate_limited"
  | "server_error"
  | "malformed_json"
  | "malformed_shape"
  | "oversized_declared"
  | "oversized_streamed"
  | "stall";

export type FakeCalendarMode =
  | "success"
  | "unauthorized"
  | "permission_denied"
  | "quota_exceeded"
  | "rate_limited"
  | "not_found"
  | "server_error"
  | "malformed_json"
  | "malformed_shape"
  | "oversized_declared"
  | "oversized_streamed"
  | "stall";

export interface FakeCalendarFixture {
  id: string;
  summary: string;
  description?: string;
  timeZone?: string;
  accessRole: "freeBusyReader" | "reader" | "writer" | "owner";
  primary?: boolean;
  selected?: boolean;
}

export interface FakeEventBoundary {
  date?: string;
  dateTime?: string;
  timeZone?: string;
}

export interface FakeEventFixture {
  id: string;
  status: "confirmed" | "tentative" | "cancelled";
  updated: string;
  summary?: string;
  description?: string;
  location?: string;
  transparency?: "opaque" | "transparent";
  start?: FakeEventBoundary;
  end?: FakeEventBoundary;
  recurringEventId?: string;
  originalStartTime?: FakeEventBoundary;
}

export interface FakeCalendarPage {
  items: FakeCalendarFixture[];
  nextPageToken?: string;
}

export interface FakeEventsPage {
  calendarId: string;
  items: FakeEventFixture[];
  nextPageToken?: string;
}

export interface FakeGoogleConfiguration {
  authorization?: "success" | "access_denied" | "unknown_error";
  token?: FakeTokenMode;
  refresh?: FakeRefreshMode;
  calendar?: FakeCalendarMode;
  calendarEnabled?: boolean;
  calendarDelayMs?: number;
  subject?: string;
  email?: string;
  calendarPages?: FakeCalendarPage[];
  eventPages?: FakeEventsPage[];
}

export interface FakeGoogleStats {
  authorizationRequests: number;
  tokenRequests: number;
  uniqueCodeExchanges: number;
  refreshRequests: number;
  successfulRefreshes: number;
  revokeCalls: number;
  calendarCalls: number;
  calendarListCalls: number;
  eventCalls: number;
  rejectedRequests: number;
}
