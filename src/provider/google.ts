import { isRecord } from "../contracts/common";
import type {
  ProviderAllDayBoundary,
  ProviderCalendar,
  ProviderError,
  ProviderEvent,
  ProviderEventBoundary,
  ProviderEventType,
  ProviderOutcome,
  ProviderPage,
  ProviderSelfResponse,
  ProviderTimedBoundary,
} from "./types";

const configurationBrand = Symbol("GoogleProviderConfiguration");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const RFC3339_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/u;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_ERROR_BYTES = 16_384;
const MAX_ITEMS = 250;
const MAX_TOKEN_BYTES = 16_384;
const MAX_ID_BYTES = 4_096;
const MAX_PAGE_TOKEN_BYTES = 1_024;
const MAX_TIME_ZONE_BYTES = 256;
const MAX_TITLE_BYTES = 2_048;
const MAX_DESCRIPTION_BYTES = 32_768;
const MAX_CALENDAR_NAME_CHARACTERS = 500;
const MAX_CALENDAR_DESCRIPTION_CHARACTERS = 4_000;
const MAX_CALENDAR_TIME_ZONE_CHARACTERS = 100;
const PRINTABLE_PAGE_TOKEN_PATTERN = /^[\u0020-\u007e]+$/u;
const CALENDAR_COLOR_PATTERN = /^#[0-9a-f]{6}$/iu;
const MAX_RETRY_AFTER_SECONDS = 3_600;
const MAX_EVENT_RANGE_MS = 93 * 24 * 60 * 60 * 1_000;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_TIMEOUT_MS = 30_000;

export interface GoogleProviderConfiguration {
  readonly tokenEndpoint: URL;
  readonly revocationEndpoint: URL;
  readonly calendarApiOrigin: URL;
  readonly [configurationBrand]: true;
}

export interface GoogleRequestOptions {
  readonly configuration?: GoogleProviderConfiguration;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}

export interface GoogleTokenRefreshRequest extends GoogleRequestOptions {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly refreshToken: string;
}

export interface GoogleTokenRefresh {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly scope?: string;
  readonly refreshToken?: string;
}

export interface GoogleRevocationRequest extends GoogleRequestOptions {
  readonly token: string;
}

export interface GoogleCalendarListRequest extends GoogleRequestOptions {
  readonly accessToken: string;
  readonly pageToken?: string;
}

export interface GoogleEventsListRequest extends GoogleRequestOptions {
  readonly accessToken: string;
  readonly calendarId: string;
  readonly timeMin: string;
  readonly timeMax: string;
  readonly pageToken?: string;
}

export function googleProductionConfiguration(): GoogleProviderConfiguration {
  return makeConfiguration(
    new URL("https://oauth2.googleapis.com/token"),
    new URL("https://oauth2.googleapis.com/revoke"),
    new URL("https://www.googleapis.com"),
  );
}

/** Explicitly named escape hatch for local deterministic tests. Never derive this from provider data. */
export function googleTestConfiguration(endpoints: {
  readonly tokenEndpoint: string;
  readonly revocationEndpoint: string;
  readonly calendarApiOrigin: string;
}): GoogleProviderConfiguration {
  return makeConfiguration(
    parseTestEndpoint(endpoints.tokenEndpoint, false),
    parseTestEndpoint(endpoints.revocationEndpoint, false),
    parseTestEndpoint(endpoints.calendarApiOrigin, true),
  );
}

function makeConfiguration(
  tokenEndpoint: URL,
  revocationEndpoint: URL,
  calendarApiOrigin: URL,
): GoogleProviderConfiguration {
  const token = tokenEndpoint.href;
  const revocation = revocationEndpoint.href;
  const calendar = calendarApiOrigin.href;
  return Object.freeze({
    get tokenEndpoint(): URL {
      return new URL(token);
    },
    get revocationEndpoint(): URL {
      return new URL(revocation);
    },
    get calendarApiOrigin(): URL {
      return new URL(calendar);
    },
    [configurationBrand]: true as const,
  });
}

function parseTestEndpoint(value: string, originOnly: boolean): URL {
  const url = new URL(value);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
    throw new TypeError("test provider endpoint must be an HTTP(S) URL without credentials");
  }
  if (originOnly && (url.pathname !== "/" || url.search || url.hash)) {
    throw new TypeError("test Calendar API endpoint must contain only an origin");
  }
  url.hash = "";
  return url;
}

function configuration(options: GoogleRequestOptions): GoogleProviderConfiguration {
  const value = options.configuration ?? googleProductionConfiguration();
  if ((value as unknown as Record<PropertyKey, unknown>)[configurationBrand] !== true) {
    throw new TypeError(
      "provider configuration must be constructed by a Google configuration factory",
    );
  }
  return value;
}

function invalidRequest(): ProviderOutcome<never> {
  return failure("invalid_request", "Provider request is invalid.");
}

function failure(
  code: ProviderError["code"],
  message: string,
  retryAfterSeconds?: number,
): ProviderOutcome<never> {
  return retryAfterSeconds === undefined
    ? { ok: false, error: { code, message } }
    : { ok: false, error: { code, message, retryAfterSeconds } };
}

function boundedString(
  value: unknown,
  maximumBytes: number,
  allowEmpty = false,
): string | undefined {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) return undefined;
  return encoder.encode(value).length <= maximumBytes ? value : undefined;
}

function requestTimeout(options: GoogleRequestOptions): number {
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
    throw new TypeError("provider timeout is outside the permitted range");
  }
  return timeout;
}

async function readBounded(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) {
    throw new RangeError("provider response is too large");
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let rejectAborted: ((reason: DOMException) => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAborted = reject;
  });
  const abort = (): void => rejectAborted?.(new DOMException("aborted", "AbortError"));
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  try {
    for (;;) {
      const part = await Promise.race([reader.read(), aborted]);
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maximumBytes) throw new RangeError("provider response is too large");
      chunks.push(part.value);
    }
  } finally {
    signal.removeEventListener("abort", abort);
    void reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function isJson(response: Response): boolean {
  const contentType = response.headers.get("content-type");
  if (contentType === null) return false;
  const mediaType = (contentType.split(";", 1)[0] ?? "").trim().toLowerCase();
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

async function parseJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!isJson(response)) throw new TypeError("provider response is not JSON");
  const bytes = await readBounded(response, MAX_RESPONSE_BYTES, signal);
  return JSON.parse(decoder.decode(bytes)) as unknown;
}

function errorJson(response: Response, bytes: Uint8Array | undefined): unknown {
  if (!isJson(response) || bytes === undefined) return undefined;
  try {
    return JSON.parse(decoder.decode(bytes)) as unknown;
  } catch {
    return undefined;
  }
}

function isInvalidGrant(response: Response, bytes: Uint8Array | undefined): boolean {
  const value = errorJson(response, bytes);
  return isRecord(value) && value["error"] === "invalid_grant";
}

const CALENDAR_USAGE_REASONS = new Set([
  "userRateLimitExceeded",
  "rateLimitExceeded",
  "quotaExceeded",
  "dailyLimitExceeded",
]);

function isCalendarUsageLimit(response: Response, bytes: Uint8Array | undefined): boolean {
  const value = errorJson(response, bytes);
  if (!isRecord(value) || !isRecord(value["error"]) || !Array.isArray(value["error"]["errors"]))
    return false;
  return value["error"]["errors"].some(
    (entry) =>
      isRecord(entry) &&
      typeof entry["reason"] === "string" &&
      CALENDAR_USAGE_REASONS.has(entry["reason"]),
  );
}

function responseRetryAfter(response: Response): number | undefined {
  const value = response.headers.get("retry-after")?.trim();
  if (!value) return undefined;
  let seconds: number;
  if (/^\d+$/u.test(value)) {
    seconds = Number(value);
  } else {
    const date = Date.parse(value);
    if (!Number.isFinite(date)) return undefined;
    seconds = Math.max(0, Math.ceil((date - Date.now()) / 1_000));
  }
  if (!Number.isSafeInteger(seconds)) return undefined;
  return Math.min(seconds, MAX_RETRY_AFTER_SECONDS);
}

export function retryAfter(error: ProviderError): number | undefined {
  const value = error.retryAfterSeconds;
  return value !== undefined && Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, MAX_RETRY_AFTER_SECONDS)
    : undefined;
}

type HttpErrorPolicy = "calendar" | "token" | "default";

function httpFailure(
  response: Response,
  bytes: Uint8Array | undefined,
  policy: HttpErrorPolicy,
): ProviderOutcome<never> {
  if (policy === "token" && response.status === 400 && isInvalidGrant(response, bytes))
    return failure("reauthorization_required", "Provider reauthorization is required.");
  if (policy === "calendar" && response.status === 400)
    return failure("invalid_request", "Provider rejected the request.");
  if (policy === "calendar" && response.status === 409)
    return failure("duplicate", "Provider resource already exists.");
  if (policy === "calendar" && response.status === 412)
    return failure("precondition", "Provider precondition failed.");
  if (policy === "calendar" && response.status === 410)
    return failure("gone", "Provider resource is gone.");
  if (response.status === 401) return failure("unauthorized", "Provider authorization failed.");
  if (policy === "calendar" && response.status === 403) {
    if (isCalendarUsageLimit(response, bytes))
      return failure(
        "rate_limited",
        "Provider rate limit was reached.",
        responseRetryAfter(response),
      );
    return failure("permission_denied", "Provider permission was denied.");
  }
  if (policy === "calendar" && response.status === 404)
    return failure("not_found", "Provider resource was not found.");
  if (response.status === 403) return failure("unauthorized", "Provider authorization failed.");
  if (response.status === 429)
    return failure(
      "rate_limited",
      "Provider rate limit was reached.",
      responseRetryAfter(response),
    );
  if (response.status >= 500)
    return failure(
      "unavailable",
      "Provider is temporarily unavailable.",
      responseRetryAfter(response),
    );
  return failure("invalid_response", "Provider rejected the request.");
}

async function execute<T>(
  url: URL,
  init: RequestInit,
  options: GoogleRequestOptions,
  consume: (response: Response, signal: AbortSignal) => Promise<T>,
  errorPolicy: HttpErrorPolicy = "default",
): Promise<ProviderOutcome<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeout(options));
  try {
    const response = await (options.fetch ?? fetch)(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
    });
    if (response.ok) {
      try {
        return { ok: true, value: await consume(response, controller.signal) };
      } catch {
        if (controller.signal.aborted) throw new DOMException("aborted", "AbortError");
        return failure("invalid_response", "Provider returned an invalid response.");
      }
    }
    let bytes: Uint8Array | undefined;
    try {
      bytes = await readBounded(response, MAX_ERROR_BYTES, controller.signal);
    } catch {
      if (controller.signal.aborted) throw new DOMException("aborted", "AbortError");
    }
    return httpFailure(response, bytes, errorPolicy);
  } catch {
    if (controller.signal.aborted) return failure("timeout", "Provider request timed out.");
    return failure("network", "Provider request failed.");
  } finally {
    clearTimeout(timer);
  }
}

function jsonRequest(
  url: URL,
  init: RequestInit,
  options: GoogleRequestOptions,
  errorPolicy: HttpErrorPolicy = "default",
): Promise<ProviderOutcome<unknown>> {
  return execute(url, init, options, parseJson, errorPolicy);
}

function bearer(accessToken: string): Headers {
  if (boundedString(accessToken, MAX_TOKEN_BYTES) === undefined)
    throw new TypeError("invalid access token");
  return new Headers({ authorization: `Bearer ${accessToken}`, accept: "application/json" });
}

export async function refreshGoogleToken(
  request: GoogleTokenRefreshRequest,
): Promise<ProviderOutcome<GoogleTokenRefresh>> {
  if (
    boundedString(request.clientId, MAX_ID_BYTES) === undefined ||
    boundedString(request.clientSecret, MAX_TOKEN_BYTES) === undefined ||
    boundedString(request.refreshToken, MAX_TOKEN_BYTES) === undefined
  )
    return invalidRequest();
  const body = new URLSearchParams({
    client_id: request.clientId,
    client_secret: request.clientSecret,
    refresh_token: request.refreshToken,
    grant_type: "refresh_token",
  });
  const result = await jsonRequest(
    configuration(request).tokenEndpoint,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body,
    },
    request,
    "token",
  );
  if (!result.ok) return result;
  const value = result.value;
  if (!isRecord(value))
    return failure("invalid_response", "Provider returned an invalid response.");
  const accessToken = boundedString(value["access_token"], MAX_TOKEN_BYTES);
  const tokenType = value["token_type"];
  const expires = value["expires_in"];
  const scope =
    value["scope"] === undefined ? undefined : boundedString(value["scope"], MAX_DESCRIPTION_BYTES);
  const rotated =
    value["refresh_token"] === undefined
      ? undefined
      : boundedString(value["refresh_token"], MAX_TOKEN_BYTES);
  if (
    !accessToken ||
    typeof tokenType !== "string" ||
    tokenType.toLowerCase() !== "bearer" ||
    typeof expires !== "number" ||
    !Number.isSafeInteger(expires) ||
    expires < 1 ||
    expires > 86_400 ||
    (value["scope"] !== undefined && scope === undefined) ||
    (value["refresh_token"] !== undefined && rotated === undefined)
  ) {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
  return {
    ok: true,
    value: {
      accessToken,
      expiresInSeconds: expires,
      ...(scope === undefined ? {} : { scope }),
      ...(rotated === undefined ? {} : { refreshToken: rotated }),
    },
  };
}

export async function revokeGoogleTokenBestEffort(
  request: GoogleRevocationRequest,
): Promise<ProviderOutcome<undefined>> {
  if (boundedString(request.token, MAX_TOKEN_BYTES) === undefined) return invalidRequest();
  return execute(
    configuration(request).revocationEndpoint,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ token: request.token }),
    },
    request,
    async (response, signal) => {
      await readBounded(response, MAX_ERROR_BYTES, signal);
      return undefined;
    },
  );
}

function validPageToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    PRINTABLE_PAGE_TOKEN_PATTERN.test(value) &&
    encoder.encode(value).length <= MAX_PAGE_TOKEN_BYTES
  );
}

function pageToken(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  return validPageToken(value) ? value : null;
}

function addPageToken(url: URL, token: string | undefined): boolean {
  if (token === undefined) return true;
  if (!validPageToken(token)) return false;
  url.searchParams.set("pageToken", token);
  return true;
}

function timeZone(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  const zone = boundedString(value, MAX_TIME_ZONE_BYTES);
  if (!zone) return null;
  try {
    new Intl.DateTimeFormat("en", { timeZone: zone });
    return zone;
  } catch {
    return null;
  }
}

function optionalText(
  value: unknown,
  maximumBytes: number,
  maximumCharacters?: number,
): string | undefined | null {
  if (value === undefined) return undefined;
  const text = boundedString(value, maximumBytes, true);
  if (
    text === undefined ||
    (maximumCharacters !== undefined && Array.from(text).length > maximumCharacters)
  ) {
    return null;
  }
  return text;
}

function normalizeCalendar(value: unknown): ProviderCalendar | undefined {
  if (!isRecord(value)) return undefined;
  const id = boundedString(value["id"], MAX_ID_BYTES);
  // A person's own name for a calendar is the one they recognise; an unusable one is ignored.
  const own = optionalText(value["summaryOverride"], MAX_TITLE_BYTES, MAX_CALENDAR_NAME_CHARACTERS);
  const name =
    typeof own === "string" && own !== ""
      ? own
      : optionalText(value["summary"], MAX_TITLE_BYTES, MAX_CALENDAR_NAME_CHARACTERS);
  const description = optionalText(
    value["description"],
    MAX_DESCRIPTION_BYTES,
    MAX_CALENDAR_DESCRIPTION_CHARACTERS,
  );
  const zone = timeZone(value["timeZone"]);
  const background = value["backgroundColor"];
  // Display metadata: an unusable colour is dropped, not fatal.
  const color =
    typeof background === "string" && CALENDAR_COLOR_PATTERN.test(background)
      ? background.toLowerCase()
      : undefined;
  const role = value["accessRole"];
  const access =
    role === "reader" || role === "freeBusyReader"
      ? "reader"
      : role === "writer" || role === "writerWithoutPrivateAccess"
        ? "writer"
        : role === "owner"
          ? "owner"
          : undefined;
  if (
    !id ||
    !name ||
    description === null ||
    zone === null ||
    (zone !== undefined && Array.from(zone).length > MAX_CALENDAR_TIME_ZONE_CHARACTERS) ||
    access === undefined ||
    (value["primary"] !== undefined && typeof value["primary"] !== "boolean") ||
    (value["selected"] !== undefined && typeof value["selected"] !== "boolean")
  )
    return undefined;
  return {
    id,
    name,
    access,
    primary: value["primary"] === true,
    selected: value["selected"] === true,
    ...(color === undefined ? {} : { color }),
    ...(description === undefined ? {} : { description }),
    ...(zone === undefined ? {} : { timeZone: zone }),
  };
}

function validDate(value: string): boolean {
  const match = DATE_PATTERN.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

function validDateTime(value: string): boolean {
  if (!RFC3339_PATTERN.test(value) || !validDate(value.slice(0, 10))) return false;
  const hour = Number(value.slice(11, 13));
  const minute = Number(value.slice(14, 16));
  const second = Number(value.slice(17, 19));
  return hour <= 23 && minute <= 59 && second <= 59 && Number.isFinite(Date.parse(value));
}

function boundary(value: unknown): ProviderEventBoundary | undefined {
  if (!isRecord(value)) return undefined;
  const date = value["date"];
  const dateTime = value["dateTime"];
  const zone = timeZone(value["timeZone"]);

  if (
    typeof date === "string" &&
    dateTime === undefined &&
    (zone === undefined || zone === null) &&
    validDate(date)
  ) {
    return { kind: "all_day", date } satisfies ProviderAllDayBoundary;
  }
  if (date === undefined && typeof dateTime === "string" && validDateTime(dateTime)) {
    return {
      kind: "timed",
      dateTime,
      ...(zone === undefined || zone === null ? {} : { timeZone: zone }),
    } satisfies ProviderTimedBoundary;
  }
  return undefined;
}

function boundaryBefore(left: ProviderEventBoundary, right: ProviderEventBoundary): boolean {
  if (left.kind !== right.kind) return false;
  return left.kind === "all_day"
    ? left.date <= (right as ProviderAllDayBoundary).date
    : Date.parse(left.dateTime) <= Date.parse((right as ProviderTimedBoundary).dateTime);
}

const EVENT_TYPES: Readonly<Record<string, ProviderEventType>> = {
  default: "default",
  focusTime: "focus_time",
  outOfOffice: "out_of_office",
  workingLocation: "working_location",
  birthday: "birthday",
  fromGmail: "from_gmail",
};

const SELF_RESPONSES: Readonly<Record<string, ProviderSelfResponse>> = {
  accepted: "accepted",
  declined: "declined",
  tentative: "tentative",
  needsAction: "needs_action",
};

/** Requests ask Google for at most the person's own attendee entry; no other attendee is read. */
function selfResponse(value: unknown): ProviderSelfResponse | undefined {
  if (!Array.isArray(value)) return undefined;
  for (const attendee of value) {
    if (!isRecord(attendee) || attendee["self"] !== true) continue;
    const response = attendee["responseStatus"];
    return typeof response === "string" && Object.hasOwn(SELF_RESPONSES, response)
      ? SELF_RESPONSES[response]
      : undefined;
  }
  return undefined;
}

function normalizeEvent(value: unknown, allowIdOnly = false): ProviderEvent | undefined {
  if (!isRecord(value)) return undefined;
  const id = boundedString(value["id"], 1024);
  const etag = boundedString(value["etag"], 256);
  const status =
    value["status"] ??
    (allowIdOnly && Object.keys(value).every((key) => key === "id") ? "cancelled" : undefined);
  const updatedAt = boundedString(value["updated"], 64);
  const hasStart = Object.hasOwn(value, "start");
  const hasEnd = Object.hasOwn(value, "end");
  const start = hasStart ? boundary(value["start"]) : undefined;
  const end = hasEnd ? boundary(value["end"]) : undefined;
  const title = optionalText(value["summary"], 4_000, 1_000);
  const description = optionalText(value["description"], 64_000, 16_000);
  const location = optionalText(value["location"], 4_000, 1_000);
  const transparency =
    value["transparency"] === undefined || value["transparency"] === "opaque"
      ? "opaque"
      : value["transparency"] === "transparent"
        ? "transparent"
        : undefined;
  const providerType = value["eventType"];
  // A type Google adds later is still an event; it reads as an ordinary one.
  const type =
    typeof providerType === "string" && Object.hasOwn(EVENT_TYPES, providerType)
      ? (EVENT_TYPES[providerType] ?? "default")
      : "default";
  const response = selfResponse(value["attendees"]);
  const recurringEventId =
    value["recurringEventId"] === undefined
      ? undefined
      : boundedString(value["recurringEventId"], 1024);
  const originalStart =
    value["originalStartTime"] === undefined ? undefined : boundary(value["originalStartTime"]);
  const validBoundaries =
    status === "cancelled" && !hasStart && !hasEnd
      ? true
      : hasStart &&
        hasEnd &&
        start !== undefined &&
        end !== undefined &&
        boundaryBefore(start, end);
  if (
    !id ||
    (status !== "cancelled" && (!updatedAt || !etag)) ||
    (updatedAt !== undefined && !validDateTime(updatedAt)) ||
    (value["etag"] !== undefined && (etag === undefined || !/^[\x21-\x7e]+$/u.test(etag))) ||
    (status !== "confirmed" && status !== "tentative" && status !== "cancelled") ||
    !validBoundaries ||
    title === null ||
    description === null ||
    location === null ||
    !transparency ||
    (value["recurringEventId"] !== undefined && recurringEventId === undefined) ||
    (value["originalStartTime"] !== undefined && originalStart === undefined) ||
    (originalStart === undefined) !== (recurringEventId === undefined) ||
    (originalStart !== undefined && start !== undefined && originalStart.kind !== start.kind)
  )
    return undefined;
  const common = {
    id,
    ...(updatedAt === undefined ? {} : { updatedAt }),
    ...(etag === undefined ? {} : { etag }),
    transparency,
    type,
    ...(response === undefined ? {} : { selfResponse: response }),
    ...(title === undefined ? {} : { title }),
    ...(description === undefined ? {} : { description }),
    ...(location === undefined ? {} : { location }),
    ...(recurringEventId === undefined || originalStart === undefined
      ? {}
      : { recurrence: { seriesId: recurringEventId, originalStart } }),
  } as const;
  if (status === "cancelled") {
    return {
      ...common,
      status,
      ...(start === undefined ? {} : { start }),
      ...(end === undefined ? {} : { end }),
    };
  }
  if (start === undefined || end === undefined || updatedAt === undefined || etag === undefined)
    return undefined;
  return { ...common, updatedAt, etag, status, start, end };
}

function normalizePage<T>(
  value: unknown,
  requestedPageToken: string | undefined,
  normalize: (item: unknown) => T | undefined,
  omitInvalid = false,
): ProviderOutcome<ProviderPage<T>> {
  if (!isRecord(value) || !Array.isArray(value["items"]) || value["items"].length > MAX_ITEMS) {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
  const next = pageToken(value["nextPageToken"]);
  if (next === null || (requestedPageToken !== undefined && next === requestedPageToken)) {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
  const sync = pageToken(value["nextSyncToken"]);
  if (sync === null || (sync !== undefined && next !== undefined))
    return failure("invalid_response", "Provider returned an invalid response.");
  let omittedCount = 0;
  const items: T[] = [];
  for (const item of value["items"]) {
    const normalized = normalize(item);
    if (normalized === undefined) {
      if (!omitInvalid)
        return failure("invalid_response", "Provider returned an invalid response.");
      omittedCount += 1;
      continue;
    }
    items.push(normalized);
  }
  return {
    ok: true,
    value: {
      items,
      ...(omitInvalid ? { omittedCount } : {}),
      ...(sync === undefined ? {} : { nextSyncToken: sync }),
      ...(next === undefined ? {} : { nextPageToken: next }),
    },
  };
}

export async function listGoogleCalendarsPage(
  request: GoogleCalendarListRequest,
): Promise<ProviderOutcome<ProviderPage<ProviderCalendar>>> {
  const url = new URL(
    "/calendar/v3/users/me/calendarList",
    configuration(request).calendarApiOrigin,
  );
  url.searchParams.set("maxResults", String(MAX_ITEMS));
  url.searchParams.set(
    "fields",
    "nextPageToken,items(id,summary,summaryOverride,description,timeZone,accessRole,primary,selected,backgroundColor)",
  );
  if (!addPageToken(url, request.pageToken))
    return failure("invalid_response", "Provider returned an invalid response.");
  let headers: Headers;
  try {
    headers = bearer(request.accessToken);
  } catch {
    return invalidRequest();
  }
  const result = await jsonRequest(url, { method: "GET", headers }, request, "calendar");
  return result.ok ? normalizePage(result.value, request.pageToken, normalizeCalendar) : result;
}

export async function listGoogleEventsPage(
  request: GoogleEventsListRequest,
): Promise<ProviderOutcome<ProviderPage<ProviderEvent>>> {
  const minimum = Date.parse(request.timeMin);
  const maximum = Date.parse(request.timeMax);
  if (
    boundedString(request.calendarId, MAX_ID_BYTES) === undefined ||
    boundedString(request.timeMin, 64) === undefined ||
    boundedString(request.timeMax, 64) === undefined ||
    !validDateTime(request.timeMin) ||
    !validDateTime(request.timeMax) ||
    !Number.isFinite(minimum) ||
    !Number.isFinite(maximum) ||
    minimum >= maximum ||
    maximum - minimum > MAX_EVENT_RANGE_MS
  )
    return invalidRequest();
  const origin = configuration(request).calendarApiOrigin;
  const url = new URL(
    `/calendar/v3/calendars/${encodeURIComponent(request.calendarId)}/events`,
    origin,
  );
  url.searchParams.set("maxResults", String(MAX_ITEMS));
  url.searchParams.set("singleEvents", "true");
  url.searchParams.set("orderBy", "startTime");
  url.searchParams.set("timeMin", request.timeMin);
  url.searchParams.set("timeMax", request.timeMax);
  url.searchParams.set("maxAttendees", MAX_ATTENDEES);
  url.searchParams.set("fields", EVENTS_FIELDS);
  if (!addPageToken(url, request.pageToken))
    return failure("invalid_response", "Provider returned an invalid response.");
  let headers: Headers;
  try {
    headers = bearer(request.accessToken);
  } catch {
    return invalidRequest();
  }
  const result = await jsonRequest(url, { method: "GET", headers }, request, "calendar");
  return result.ok ? normalizePage(result.value, request.pageToken, normalizeEvent, true) : result;
}

const EVENT_FIELDS =
  "id,etag,status,updated,summary,description,location,transparency,eventType,attendees(self,responseStatus),start(date,dateTime,timeZone),end(date,dateTime,timeZone),recurringEventId,originalStartTime(date,dateTime,timeZone)";
/** With more attendees than this, Google returns only the person's own entry. */
const MAX_ATTENDEES = "1";
const EVENTS_FIELDS = `nextPageToken,items(${EVENT_FIELDS})`;

export interface GoogleChangesListRequest extends GoogleRequestOptions {
  readonly accessToken: string;
  readonly calendarId: string;
  readonly syncToken?: string;
  readonly pageToken?: string;
}

export async function listGoogleChangesPage(
  request: GoogleChangesListRequest,
): Promise<ProviderOutcome<ProviderPage<ProviderEvent>>> {
  const url = new URL(
    `/calendar/v3/calendars/${encodeURIComponent(request.calendarId)}/events`,
    configuration(request).calendarApiOrigin,
  );
  url.searchParams.set("maxResults", String(MAX_ITEMS));
  url.searchParams.set("showDeleted", "true");
  url.searchParams.set("singleEvents", "false");
  url.searchParams.set("maxAttendees", MAX_ATTENDEES);
  url.searchParams.set("fields", `nextSyncToken,${EVENTS_FIELDS}`);
  if (request.syncToken !== undefined) {
    if (!validPageToken(request.syncToken)) return invalidRequest();
    url.searchParams.set("syncToken", request.syncToken);
  }
  if (!addPageToken(url, request.pageToken)) return invalidRequest();
  const result = await jsonRequest(
    url,
    { method: "GET", headers: bearer(request.accessToken) },
    request,
    "calendar",
  );
  if (!result.ok) return result;
  const page = normalizePage(
    result.value,
    request.pageToken,
    (item) => normalizeEvent(item, true),
    true,
  );
  if (page.ok && page.value.nextPageToken === undefined && page.value.nextSyncToken === undefined)
    return failure("invalid_response", "Provider returned an invalid response.");
  return page;
}

export interface GoogleEventRequest extends GoogleRequestOptions {
  readonly accessToken: string;
  readonly calendarId: string;
  readonly eventId: string;
  readonly method: "GET" | "POST" | "PATCH" | "DELETE";
  readonly body?: Readonly<Record<string, unknown>>;
  readonly ifMatch?: string;
}

export async function requestGoogleEvent(
  request: GoogleEventRequest,
): Promise<ProviderOutcome<ProviderEvent | undefined>> {
  const path = `/calendar/v3/calendars/${encodeURIComponent(request.calendarId)}/events`;
  const url = new URL(
    request.method === "POST" ? path : `${path}/${encodeURIComponent(request.eventId)}`,
    configuration(request).calendarApiOrigin,
  );
  if (request.method !== "DELETE") {
    url.searchParams.set("fields", EVENT_FIELDS);
    url.searchParams.set("maxAttendees", MAX_ATTENDEES);
  }
  if (request.method !== "GET") url.searchParams.set("sendUpdates", "none");
  const headers = bearer(request.accessToken);
  if (request.ifMatch !== undefined) headers.set("If-Match", request.ifMatch);
  if (request.body !== undefined) headers.set("content-type", "application/json");
  return execute(
    url,
    {
      method: request.method,
      headers,
      ...(request.body === undefined ? {} : { body: JSON.stringify(request.body) }),
    },
    request,
    async (response, signal) => {
      if (request.method === "DELETE") {
        await readBounded(response, MAX_ERROR_BYTES, signal);
        return undefined;
      }
      const event = normalizeEvent(await parseJson(response, signal), request.method === "GET");
      if (event === undefined) throw new TypeError("invalid provider event");
      return event;
    },
    "calendar",
  );
}
