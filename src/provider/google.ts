import type {
  ProviderAllDayBoundary,
  ProviderCalendar,
  ProviderError,
  ProviderEvent,
  ProviderEventBoundary,
  ProviderOutcome,
  ProviderPage,
  ProviderTimedBoundary,
} from "./types";

const configurationBrand = Symbol("GoogleProviderConfiguration");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const RFC3339_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/u;
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_ERROR_BYTES = 16_384;
const MAX_ITEMS = 250;
const MAX_TOKEN_BYTES = 16_384;
const MAX_ID_BYTES = 4_096;
const MAX_PAGE_TOKEN_BYTES = 8_192;
const MAX_TIME_ZONE_BYTES = 256;
const MAX_TITLE_BYTES = 2_048;
const MAX_DESCRIPTION_BYTES = 32_768;
const MAX_LOCATION_BYTES = 8_192;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requestTimeout(options: GoogleRequestOptions): number {
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
    throw new TypeError("provider timeout is outside the permitted range");
  }
  return timeout;
}

async function readBounded(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) {
    throw new RangeError("provider response is too large");
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maximumBytes) throw new RangeError("provider response is too large");
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
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

async function parseJson(response: Response): Promise<unknown> {
  if (!isJson(response)) throw new TypeError("provider response is not JSON");
  const bytes = await readBounded(response, response.ok ? MAX_RESPONSE_BYTES : MAX_ERROR_BYTES);
  return JSON.parse(decoder.decode(bytes)) as unknown;
}

function retryAfter(response: Response): number | undefined {
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

async function execute(
  url: URL,
  init: RequestInit,
  options: GoogleRequestOptions,
): Promise<ProviderOutcome<Response>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeout(options));
  try {
    const response = await (options.fetch ?? fetch)(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
    });
    if (response.ok) return { ok: true, value: response };
    await readBounded(response, MAX_ERROR_BYTES).catch(() => undefined);
    if (response.status === 401 || response.status === 403)
      return failure("unauthorized", "Provider authorization failed.");
    if (response.status === 429)
      return failure("rate_limited", "Provider rate limit was reached.", retryAfter(response));
    if (response.status >= 500)
      return failure("unavailable", "Provider is temporarily unavailable.", retryAfter(response));
    return failure("invalid_response", "Provider rejected the request.");
  } catch {
    if (controller.signal.aborted) return failure("timeout", "Provider request timed out.");
    return failure("network", "Provider request failed.");
  } finally {
    clearTimeout(timer);
  }
}

async function jsonRequest(
  url: URL,
  init: RequestInit,
  options: GoogleRequestOptions,
): Promise<ProviderOutcome<unknown>> {
  const response = await execute(url, init, options);
  if (!response.ok) return response;
  try {
    return { ok: true, value: await parseJson(response.value) };
  } catch {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
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
  const result = await execute(
    configuration(request).revocationEndpoint,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ token: request.token }),
    },
    request,
  );
  if (!result.ok) return result;
  try {
    await readBounded(result.value, MAX_ERROR_BYTES);
    return { ok: true, value: undefined };
  } catch {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
}

function pageToken(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  return boundedString(value, MAX_PAGE_TOKEN_BYTES) ?? null;
}

function addPageToken(url: URL, token: string | undefined): boolean {
  if (token === undefined) return true;
  if (boundedString(token, MAX_PAGE_TOKEN_BYTES) === undefined) return false;
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

function optionalText(value: unknown, maximumBytes: number): string | undefined | null {
  if (value === undefined) return undefined;
  return boundedString(value, maximumBytes, true) ?? null;
}

function normalizeCalendar(value: unknown): ProviderCalendar | undefined {
  if (!isRecord(value)) return undefined;
  const id = boundedString(value["id"], MAX_ID_BYTES);
  const name = boundedString(value["summary"], MAX_TITLE_BYTES, true);
  const description = optionalText(value["description"], MAX_DESCRIPTION_BYTES);
  const zone = timeZone(value["timeZone"]);
  const role = value["accessRole"];
  const access =
    role === "reader" || role === "freeBusyReader"
      ? "reader"
      : role === "writer"
        ? "writer"
        : role === "owner"
          ? "owner"
          : undefined;
  if (
    !id ||
    name === undefined ||
    description === null ||
    zone === null ||
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

function zoneMatchesDateTime(dateTime: string, zone: string): boolean {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(dateTime));
  const values = new Map(parts.map((part) => [part.type, part.value]));
  const local = `${values.get("year")}-${values.get("month")}-${values.get("day")}T${values.get("hour")}:${values.get("minute")}:${values.get("second")}`;
  return local === dateTime.slice(0, 19);
}

function boundary(value: unknown): ProviderEventBoundary | undefined {
  if (!isRecord(value)) return undefined;
  const date = value["date"];
  const dateTime = value["dateTime"];
  const zone = timeZone(value["timeZone"]);
  if (zone === null) return undefined;
  if (typeof date === "string" && dateTime === undefined && zone === undefined && validDate(date)) {
    return { kind: "all_day", date } satisfies ProviderAllDayBoundary;
  }
  if (
    date === undefined &&
    typeof dateTime === "string" &&
    validDateTime(dateTime) &&
    (zone === undefined || zoneMatchesDateTime(dateTime, zone))
  ) {
    return {
      kind: "timed",
      dateTime,
      ...(zone === undefined ? {} : { timeZone: zone }),
    } satisfies ProviderTimedBoundary;
  }
  return undefined;
}

function boundaryBefore(left: ProviderEventBoundary, right: ProviderEventBoundary): boolean {
  if (left.kind !== right.kind) return false;
  return left.kind === "all_day"
    ? left.date < (right as ProviderAllDayBoundary).date
    : Date.parse(left.dateTime) < Date.parse((right as ProviderTimedBoundary).dateTime);
}

function normalizeEvent(value: unknown): ProviderEvent | undefined {
  if (!isRecord(value)) return undefined;
  const id = boundedString(value["id"], MAX_ID_BYTES);
  const status = value["status"];
  const hasStart = Object.hasOwn(value, "start");
  const hasEnd = Object.hasOwn(value, "end");
  const start = hasStart ? boundary(value["start"]) : undefined;
  const end = hasEnd ? boundary(value["end"]) : undefined;
  const title = optionalText(value["summary"], MAX_TITLE_BYTES);
  const description = optionalText(value["description"], MAX_DESCRIPTION_BYTES);
  const location = optionalText(value["location"], MAX_LOCATION_BYTES);
  const transparency =
    value["transparency"] === undefined || value["transparency"] === "opaque"
      ? "opaque"
      : value["transparency"] === "transparent"
        ? "transparent"
        : undefined;
  const recurringEventId =
    value["recurringEventId"] === undefined
      ? undefined
      : boundedString(value["recurringEventId"], MAX_ID_BYTES);
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
    (status !== "confirmed" && status !== "tentative" && status !== "cancelled") ||
    !validBoundaries ||
    title === null ||
    description === null ||
    location === null ||
    !transparency ||
    (value["recurringEventId"] !== undefined && recurringEventId === undefined) ||
    (value["originalStartTime"] !== undefined && originalStart === undefined) ||
    (originalStart !== undefined && recurringEventId === undefined)
  )
    return undefined;
  const common = {
    id,
    transparency,
    ...(title === undefined ? {} : { title }),
    ...(description === undefined ? {} : { description }),
    ...(location === undefined ? {} : { location }),
    ...(recurringEventId === undefined ? {} : { recurringEventId }),
    ...(originalStart === undefined ? {} : { originalStart }),
  } as const;
  if (status === "cancelled") {
    return {
      ...common,
      status,
      ...(start === undefined ? {} : { start }),
      ...(end === undefined ? {} : { end }),
    };
  }
  if (start === undefined || end === undefined) return undefined;
  return { ...common, status, start, end };
}

function normalizePage<T>(
  value: unknown,
  requestedPageToken: string | undefined,
  normalize: (item: unknown) => T | undefined,
): ProviderOutcome<ProviderPage<T>> {
  if (!isRecord(value) || !Array.isArray(value["items"]) || value["items"].length > MAX_ITEMS) {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
  const next = pageToken(value["nextPageToken"]);
  if (next === null || (requestedPageToken !== undefined && next === requestedPageToken)) {
    return failure("invalid_response", "Provider returned an invalid response.");
  }
  const items: T[] = [];
  for (const item of value["items"]) {
    const normalized = normalize(item);
    if (normalized === undefined)
      return failure("invalid_response", "Provider returned an invalid response.");
    items.push(normalized);
  }
  return { ok: true, value: { items, ...(next === undefined ? {} : { nextPageToken: next }) } };
}

export async function listGoogleCalendarsPage(
  request: GoogleCalendarListRequest,
): Promise<ProviderOutcome<ProviderPage<ProviderCalendar>>> {
  const url = new URL(
    "/calendar/v3/users/me/calendarList",
    configuration(request).calendarApiOrigin,
  );
  url.searchParams.set("maxResults", String(MAX_ITEMS));
  if (!addPageToken(url, request.pageToken)) return invalidRequest();
  let headers: Headers;
  try {
    headers = bearer(request.accessToken);
  } catch {
    return invalidRequest();
  }
  const result = await jsonRequest(url, { method: "GET", headers }, request);
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
  url.searchParams.set("timeMin", request.timeMin);
  url.searchParams.set("timeMax", request.timeMax);
  if (!addPageToken(url, request.pageToken)) return invalidRequest();
  let headers: Headers;
  try {
    headers = bearer(request.accessToken);
  } catch {
    return invalidRequest();
  }
  const result = await jsonRequest(url, { method: "GET", headers }, request);
  return result.ok ? normalizePage(result.value, request.pageToken, normalizeEvent) : result;
}
