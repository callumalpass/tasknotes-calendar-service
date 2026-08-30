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
export type FakeCalendarMode = "success" | "rate_limited" | "malformed";
export interface FakeGoogleConfiguration {
  authorization?: "success" | "access_denied" | "unknown_error";
  token?: FakeTokenMode;
  calendar?: FakeCalendarMode;
  calendarEnabled?: boolean;
  subject?: string;
  email?: string;
}
export interface FakeGoogleStats {
  authorizationRequests: number;
  tokenRequests: number;
  uniqueCodeExchanges: number;
  revokeCalls: number;
  calendarCalls: number;
  rejectedRequests: number;
}
