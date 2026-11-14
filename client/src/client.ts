import type { z } from "zod/v4";

import {
  bearerSessionSchema,
  calendarsSchema,
  connectionsSchema,
  currentSessionSchema,
  errorSchema,
  eventId,
  id,
  pageSchema,
  redeemedConnectionSchema,
  scheduledEventSchema,
  selectionSchema,
  sessionSchema,
  startSchema,
  statusSchema,
  type EventBoundary,
  type EventFields,
  type EventPage,
  type GoogleCalendar,
  type GoogleConnection,
  type GoogleEvent,
} from "./schemas.js";

const SELECTION_KEY = "tasknotes:google-calendars:v1";
// Holds no credential: it only spares everyone else a service call on load.
const SIGNED_IN_KEY = "tasknotes:google-calendar-signed-in:v1";
const MAX_RANGE_MS = 93 * 86_400_000;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_PAGES_PER_RANGE = 20;
export const MAX_SELECTED_CALENDARS = 5;

/** Where the client keeps what it may forget: a selection and a signed-in flag. */
export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** Holds a bearer credential where page script and other apps cannot read it. */
export interface CredentialStore {
  load(): Promise<string | null>;
  save(credential: string): Promise<void>;
  clear(): Promise<void>;
}

/** The window Google's consent runs in, opened during the user's gesture. */
export interface AuthorizationWindow {
  show(url: string): void | Promise<void>;
  close(): void;
}

/** What differs between the places TaskNotes runs. */
export interface CalendarServiceHost {
  clientKind: "web" | "ios" | "android" | "obsidian";
  deviceName: string;
  /** Null on the web, where the session is an HttpOnly cookie. */
  credentials: CredentialStore | null;
  /** Null when the host refused to open a window. */
  openWindow(): AuthorizationWindow | null;
}

/** The request the client makes, in the terms `fetch` takes it. */
export interface ServiceRequest {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal: AbortSignal;
  credentials: "omit" | "include";
  cache: "no-store";
  redirect: "error";
  referrerPolicy: "no-referrer";
}

export interface ServiceResponse {
  status: number;
  ok: boolean;
  json(): Promise<unknown>;
}

/**
 * `fetch`, or a stand-in for it. A stand-in rejects with a `TypeError` when the
 * service cannot be reached, as `fetch` does, and honours the signal.
 */
export type ServiceTransport = (url: string, request: ServiceRequest) => Promise<ServiceResponse>;

export interface CalendarServiceOptions {
  /** The service's origin, without a path. */
  origin: string;
  host: CalendarServiceHost;
  storage: KeyValueStore;
  transport?: ServiceTransport;
}

export type CalendarServiceFailure =
  | "authorization_failed"
  | "authorization_expired"
  | "code_rejected"
  | "conflict"
  | "invalid_authorization"
  | "invalid_request"
  | "not_found"
  | "pagination"
  | "popup_blocked"
  | "rate_limited"
  | "reconnect_required"
  | "session_expired"
  | "unavailable";

export class CalendarServiceError extends Error {
  constructor(readonly failure: CalendarServiceFailure) {
    super(failure);
  }
}

export interface CalendarServiceSnapshot {
  sessionId: string | null;
  busy: boolean;
  awaitingCode: boolean;
  failure: CalendarServiceFailure | null;
  connection: GoogleConnection | null;
  calendars: GoogleCalendar[];
  selected: string[];
}

async function failureFor(response: ServiceResponse): Promise<CalendarServiceFailure> {
  const { status } = response;
  if (status === 404) return "not_found";
  if (status === 409) {
    // A stale event and lapsed Google access both answer 409; only the code
    // tells them apart. A service that predates the code says "conflict".
    const error = errorSchema.safeParse(await response.json().catch(() => null));
    return error.success && error.data.code === "reconnect_required"
      ? "reconnect_required"
      : "conflict";
  }
  if (status === 429) return "rate_limited";
  return status >= 400 && status < 500 ? "invalid_request" : "unavailable";
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

/**
 * Until someone chooses: their primary calendar and the ones they show in
 * Google Calendar, up to the limit.
 */
export function defaultSelection(calendars: readonly GoogleCalendar[]): string[] {
  return [
    ...calendars.filter((calendar) => calendar.is_primary),
    ...calendars.filter((calendar) => calendar.is_selected && !calendar.is_primary),
  ]
    .slice(0, MAX_SELECTED_CALENDARS)
    .map((calendar) => calendar.id);
}

function storedSelection(storage: Pick<KeyValueStore, "getItem">): string[] | null {
  try {
    return selectionSchema.parse(JSON.parse(storage.getItem(SELECTION_KEY) ?? "null"));
  } catch {
    return null;
  }
}

/** Google's page is the only place the sign-in popup may be sent. */
function authorizationUrl(value: string): string {
  const url = new URL(value);
  if (
    url.origin !== "https://accounts.google.com" ||
    url.pathname !== "/o/oauth2/v2/auth" ||
    url.username ||
    url.password
  )
    throw new CalendarServiceError("invalid_authorization");
  return url.href;
}

/**
 * One signal that ends when any of these does, or when the time runs out.
 * `AbortSignal.any` and `AbortSignal.timeout` are missing from WebViews
 * TaskNotes still runs in.
 */
function anySignal(
  signals: readonly AbortSignal[],
  timeoutMs: number,
): { signal: AbortSignal; release(): void } {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException("The request timed out.", "TimeoutError"));
  }, timeoutMs);
  const releases: (() => void)[] = [() => clearTimeout(timer)];
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    const abort = () => controller.abort(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    releases.push(() => signal.removeEventListener("abort", abort));
  }
  return { signal: controller.signal, release: () => releases.forEach((release) => release()) };
}

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason as Error);
      },
      { once: true },
    );
  });
}

/**
 * Owns the polling secret and PKCE verifier in private memory: they never
 * reach interface state, storage, logs, URLs or mdbase. A web session lives in
 * the service's HttpOnly cookie, which no script here can read; any other is a
 * bearer credential held here and in the host's credential store. Google tokens
 * never reach this client.
 */
export class CalendarServiceClient {
  #session = new AbortController();
  #credential: string | null = null;
  #attempt: AbortController | null = null;
  #submitCode: ((code: string) => void) | null = null;
  #listeners = new Set<() => void>();
  #snapshot: CalendarServiceSnapshot;

  private readonly origin: string;
  private readonly host: CalendarServiceHost;
  private readonly storage: KeyValueStore;
  private readonly transport: ServiceTransport;

  constructor(options: CalendarServiceOptions) {
    this.origin = options.origin;
    this.host = options.host;
    this.storage = options.storage;
    // Native fetch requires the global receiver, not this instance.
    this.transport = options.transport ?? ((url, request) => globalThis.fetch(url, request));
    this.#snapshot = this.#signedOut();
  }

  #signedOut(): CalendarServiceSnapshot {
    return {
      sessionId: null,
      busy: false,
      awaitingCode: false,
      failure: null,
      connection: null,
      calendars: [],
      selected: storedSelection(this.storage) ?? [],
    };
  }

  getSnapshot = () => this.#snapshot;

  subscribe = (listener: () => void) => {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  };

  #publish(update: Partial<CalendarServiceSnapshot>) {
    this.#snapshot = { ...this.#snapshot, ...update };
    this.#listeners.forEach((listener) => listener());
  }

  /** Drops local authority; the server session stays until it is signed out. */
  forget = () => {
    this.#session.abort();
    this.#session = new AbortController();
    this.storage.removeItem(SIGNED_IN_KEY);
    this.#credential = null;
    void this.host.credentials?.clear();
    this.#snapshot = this.#signedOut();
    this.#listeners.forEach((listener) => listener());
  };

  async #request<T>(
    path: string,
    schema: z.ZodType<T> | null,
    options: {
      method?: string;
      body?: unknown;
      etag?: string;
      signal?: AbortSignal;
    } = {},
  ): Promise<T> {
    const session = this.#session;
    const { body, etag, signal } = options;
    const ending = anySignal([session.signal, ...(signal ? [signal] : [])], REQUEST_TIMEOUT_MS);
    let response: ServiceResponse;
    try {
      response = await this.transport(`${this.origin}${path}`, {
        method: options.method ?? (body === undefined ? "GET" : "POST"),
        credentials: this.host.credentials ? "omit" : "include",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: ending.signal,
        headers: {
          ...(this.#credential ? { Authorization: `Bearer ${this.#credential}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(etag ? { "If-Match": etag } : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } finally {
      ending.release();
    }
    session.signal.throwIfAborted();
    if (response.status === 401) {
      this.forget();
      throw new CalendarServiceError("session_expired");
    }
    if (!response.ok) {
      const failure = await failureFor(response);
      session.signal.throwIfAborted();
      if (failure === "reconnect_required") this.#lapsed();
      throw new CalendarServiceError(failure);
    }
    if (!schema) return undefined as T;
    const value = schema.parse(await response.json());
    session.signal.throwIfAborted();
    return value;
  }

  /** Google withdrew access: nothing can be read until the person reconnects. */
  #lapsed() {
    const { connection } = this.#snapshot;
    if (connection)
      this.#publish({
        connection: { ...connection, status: "reconnect_required" },
        calendars: [],
      });
  }

  async #run(action: () => Promise<void>) {
    const session = this.#session;
    this.#publish({ busy: true, failure: null });
    try {
      await action();
    } catch (reason) {
      if (session.signal.aborted || isAbort(reason)) return;
      this.#publish({
        failure: reason instanceof CalendarServiceError ? reason.failure : "unavailable",
      });
    } finally {
      if (!session.signal.aborted) this.#publish({ busy: false });
    }
  }

  /** Resumes the session after a reload; a 401 just signs out. */
  restore = async () => {
    if (!this.storage.getItem(SIGNED_IN_KEY)) return;
    await this.#run(async () => {
      if (this.host.credentials) {
        this.#credential = await this.host.credentials.load();
        if (!this.#credential) {
          this.forget();
          return;
        }
      }
      const { session_id } = await this.#request("/v1/session", currentSessionSchema);
      this.#publish({ sessionId: session_id });
      await this.#discover();
    });
  };

  signIn = () => this.#authorize("/v1/sign-in");
  connect = () => this.#authorize("/v1/connections/google");

  #authorize(base: "/v1/sign-in" | "/v1/connections/google") {
    if (this.#snapshot.busy) return Promise.resolve();
    // Open during the user gesture, before any request can lose it.
    const authorizationWindow = this.host.openWindow();
    if (!authorizationWindow) {
      this.#publish({ failure: "popup_blocked" });
      return Promise.resolve();
    }
    const attempt = new AbortController();
    this.#attempt = attempt;
    const { signal } = attempt;
    return this.#run(async () => {
      try {
        const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
        const challenge = base64Url(
          new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
        );
        const transaction = await this.#request(`${base}/start`, startSchema, {
          body: {
            client_kind: this.host.clientKind,
            device_name: this.host.deviceName,
            code_challenge: challenge,
          },
          signal,
        });
        await authorizationWindow.show(authorizationUrl(transaction.authorization_url));
        const path = `${base}/${transaction.transaction_id}`;
        const secret = { polling_secret: transaction.polling_secret };
        // The window's state proves nothing: Google's COOP severs a popup's
        // handle while consent is in progress. The transaction's expiry ends this.
        const deadline = Date.parse(transaction.expires_at);
        for (;;) {
          await delay(1500, signal);
          if (Date.now() > deadline) throw new CalendarServiceError("authorization_expired");
          const status = await this.#authorizationStatus(path, secret, signal);
          if (status === "authorized") break;
          if (status === "failed") throw new CalendarServiceError("authorization_failed");
          if (status === "expired") throw new CalendarServiceError("authorization_expired");
        }
        const proof = { ...secret, code_verifier: verifier };
        if (base === "/v1/connections/google") {
          await this.#request(`${path}/redeem`, redeemedConnectionSchema, {
            body: proof,
            signal,
          });
        } else {
          // The window keeps showing the code until this attempt finishes.
          const code = await this.#confirmationCode(signal);
          const { session } = await this.#request(
            `${path}/redeem`,
            this.host.credentials ? bearerSessionSchema : sessionSchema,
            { body: { ...proof, confirmation_code: code }, signal },
          ).catch((reason: unknown) => {
            // One wrong attempt ends the transaction on the service.
            if (
              reason instanceof CalendarServiceError &&
              reason.failure !== "rate_limited" &&
              reason.failure !== "unavailable"
            )
              throw new CalendarServiceError("code_rejected");
            throw reason;
          });
          if (session.credential) {
            await this.host.credentials?.save(session.credential);
            this.#credential = session.credential;
          }
          this.storage.setItem(SIGNED_IN_KEY, "1");
          this.#publish({ sessionId: session.session_id });
        }
        await this.#discover();
      } finally {
        authorizationWindow.close();
        this.#attempt = null;
        this.#submitCode = null;
        if (this.#snapshot.awaitingCode) this.#publish({ awaitingCode: false });
      }
    });
  }

  /** A native WebView freezes behind the system browser, stalling requests until
   * they time out, so only the service's own answer can end the attempt. */
  async #authorizationStatus(
    path: string,
    secret: { polling_secret: string },
    signal: AbortSignal,
  ) {
    try {
      const { status } = await this.#request(`${path}/status`, statusSchema, {
        body: secret,
        signal,
      });
      return status;
    } catch (reason) {
      if (signal.aborted || !isTransient(reason)) throw reason;
      return "pending";
    }
  }

  #confirmationCode(signal: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      this.#submitCode = resolve;
      signal.addEventListener("abort", () => reject(signal.reason as Error), {
        once: true,
      });
      this.#publish({ awaitingCode: true });
    });
  }

  submitCode = (code: string) => {
    this.#publish({ awaitingCode: false });
    this.#submitCode?.(code.trim().toUpperCase());
  };

  /** Stops waiting here; the service supersedes the abandoned attempt. */
  cancelAuthorization = () => this.#attempt?.abort();

  async #discover() {
    const { connections } = await this.#request("/v1/connections", connectionsSchema);
    const connection = connections[0] ?? null;
    this.#publish({ connection, calendars: [] });
    if (connection?.status !== "active") return;
    const { calendars } = await this.#request("/v1/calendars", calendarsSchema);
    this.#publish({
      calendars,
      selected: storedSelection(this.storage) ?? defaultSelection(calendars),
    });
  }

  refresh = () => this.#run(() => this.#discover());

  setSelected(selected: string[]) {
    this.storage.setItem(SELECTION_KEY, JSON.stringify(selected));
    this.#publish({ selected });
  }

  disconnect = () =>
    this.#run(async () => {
      const { connection } = this.#snapshot;
      if (!connection) return;
      await this.#request(`/v1/connections/${connection.id}`, null, {
        method: "DELETE",
      });
      this.storage.removeItem(SELECTION_KEY);
      this.#publish({ connection: null, calendars: [], selected: [] });
    });

  signOut = () =>
    this.#run(async () => {
      await this.#request(`/v1/devices/${this.#snapshot.sessionId}`, null, {
        method: "DELETE",
      });
      this.forget();
    });

  deleteAccount = () =>
    this.#run(async () => {
      await this.#request("/v1/account", null, { method: "DELETE" });
      this.storage.removeItem(SELECTION_KEY);
      this.forget();
    });

  /** Reads a visible range, which may be longer than one service request. */
  async events(
    calendarId: string,
    start: Date,
    end: Date,
    signal: AbortSignal,
  ): Promise<{ events: GoogleEvent[]; omitted: number }> {
    const events = new Map<string, GoogleEvent>();
    let omitted = 0;
    for (let from = start.getTime(); from < end.getTime(); from += MAX_RANGE_MS) {
      const range = {
        start: new Date(from).toISOString(),
        end: new Date(Math.min(from + MAX_RANGE_MS, end.getTime())).toISOString(),
      };
      let cursor: string | null = null;
      for (let page = 0; ; page++) {
        if (page === MAX_PAGES_PER_RANGE) throw new CalendarServiceError("pagination");
        const query: URLSearchParams = new URLSearchParams({
          ...range,
          ...(cursor ? { cursor } : {}),
        });
        const result: EventPage = await this.#request(
          `/v1/calendars/${id.parse(calendarId)}/events?${query}`,
          pageSchema,
          { signal },
        );
        omitted += result.omitted_count;
        for (const event of result.events) {
          if (event.status === "cancelled") events.delete(event.id);
          else events.set(event.id, event);
        }
        cursor = result.next_cursor;
        if (!cursor) break;
      }
    }
    return { events: [...events.values()], omitted };
  }

  createEvent(
    calendarId: string,
    fields: EventFields & { start: EventBoundary; end: EventBoundary },
    idempotencyKey: string,
  ): Promise<GoogleEvent> {
    return this.#request(`/v1/calendars/${id.parse(calendarId)}/events`, scheduledEventSchema, {
      body: { ...fields, idempotency_key: idempotencyKey },
    });
  }

  updateEvent(event: GoogleEvent, fields: EventFields): Promise<GoogleEvent> {
    return this.#request(eventPath(event), scheduledEventSchema, {
      method: "PATCH",
      body: fields,
      etag: event.etag,
    });
  }

  deleteEvent(event: GoogleEvent): Promise<void> {
    return this.#request(eventPath(event), null, {
      method: "DELETE",
      etag: event.etag,
    });
  }
}
function eventPath(event: GoogleEvent): string {
  return `/v1/calendars/${id.parse(event.calendar_id)}/events/${eventId.parse(event.id)}`;
}

function isTransient(reason: unknown): boolean {
  if (reason instanceof CalendarServiceError)
    return reason.failure === "unavailable" || reason.failure === "rate_limited";
  return (
    reason instanceof TypeError ||
    (reason instanceof DOMException && reason.name === "TimeoutError")
  );
}

function isAbort(reason: unknown): boolean {
  return reason instanceof Error && reason.name === "AbortError";
}
