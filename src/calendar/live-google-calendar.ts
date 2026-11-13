import type {
  Calendar,
  CalendarEvent,
  CreateEventRequest,
  PatchEventRequest,
  ChangesQuery,
  ChangesResponse,
  EventsQuery,
  EventsResponse,
} from "../contracts";
import { canonicalUuid } from "../contracts/common";
import { MAX_CALENDARS } from "../contracts/resources";
import {
  GoogleAccessTokenError,
  type AccessGrant,
  type ConnectionSnapshot,
  type GoogleAccessTokens,
} from "../connections/google-access-tokens";
import { encodeBase64Url } from "../crypto/base64url";
import { openEventCursor, sealEventCursor, CursorError } from "../crypto/cursor";
import { openEventId, createProviderEventId } from "../crypto/event-id";
import { openSyncCursor, sealSyncCursor, type SyncCursorPayload } from "../crypto/cursor";
import { randomBytes, type RandomByteSource } from "../crypto/random";
import { mapProviderEvents, EventMappingError } from "../events/map-provider-events";
import {
  listGoogleCalendarsPage,
  listGoogleEventsPage,
  listGoogleChangesPage,
  requestGoogleEvent,
  retryAfter,
  type GoogleEventRequest,
  type GoogleProviderConfiguration,
} from "../provider/google";
import type {
  ProviderCalendar,
  ProviderError,
  ProviderOutcome,
  ProviderEventBoundary,
} from "../provider/types";

// Discovery is an idempotent GET, so an expired attempt may be stolen. The lease is longer than
// the configured provider timeout and uses D1's clock so Worker clock skew cannot create overlap.
const LEASE_SECONDS = 45;
const LOSER_DELAYS_MS = [50, 100, 200, 400, 800] as const;
const RETRY_AFTER_SECONDS = 1;
const PROVIDER_PAGE_SIZE = 250;
// As many provider pages as the calendars response can carry. Their timeouts fit the lease.
const MAX_DISCOVERY_PAGES = MAX_CALENDARS / PROVIDER_PAGE_SIZE;

export type LiveGoogleCalendarErrorCode =
  | "permission_denied"
  | "sync_reset_required"
  | "invalid_request"
  | "not_found"
  | "reconnect"
  | "conflict"
  | "rate"
  | "unavailable"
  | "internal";

export class LiveGoogleCalendarError extends Error {
  public readonly code: LiveGoogleCalendarErrorCode;
  public readonly retryAfterSeconds?: number;
  /** For the request log: the provider or token failure behind this one, as a stable code. */
  public readonly detail?: string;

  public constructor(
    code: LiveGoogleCalendarErrorCode,
    retryAfterSeconds?: number,
    detail?: string,
  ) {
    super("Live calendar operation failed.");
    this.name = "LiveGoogleCalendarError";
    this.code = code;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
    if (detail !== undefined) this.detail = detail;
    Object.freeze(this);
  }
}

export interface CalendarList {
  calendars: Calendar[];
  /** Present when this request asked the provider, rather than answering from stored mappings. */
  discovery?: {
    /** Provider calendars the service cannot represent, left out of the list. */
    omittedCount: number;
    /** The provider had more calendars than the service lists. */
    truncated: boolean;
  };
}

export interface LiveGoogleCalendarDependencies {
  readonly db: D1Database;
  readonly accessTokens: GoogleAccessTokens;
  readonly environment: "local" | "lab" | "staging" | "production";
  readonly googleProvider: GoogleProviderConfiguration;
  readonly fetch: typeof fetch;
  readonly cursorKey: Uint8Array;
  readonly eventIdKey: Uint8Array;
  readonly nowEpochSeconds: () => number;
  readonly random: RandomByteSource;
  readonly uuid: () => string;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly providerTimeoutMs?: number;
}

interface AuthorityRow {
  readonly id: string;
  readonly principal_id: string;
  readonly status: "active" | "reconnect_required";
  readonly generation: number;
  readonly token_version: number;
  readonly principal_generation: number;
  readonly discovery_lease_owner: string | null;
  readonly discovery_lease_until: number | null;
  readonly discovery_version: number;
  readonly server_now: number;
}

interface DiscoveryRow extends AuthorityRow {
  readonly discovered_at: number | null;
}

interface CalendarRow {
  readonly id: string;
  readonly connection_id: string;
  readonly name: string;
  readonly description: string | null;
  readonly access_role: "reader" | "writer" | "owner";
  readonly time_zone: string | null;
  readonly is_primary: number;
  readonly is_selected: number;
  readonly color: string | null;
}

interface EventGrantRow extends AuthorityRow {
  readonly calendar_id: string;
  readonly provider_calendar_id: string;
  readonly access_role: "reader" | "writer" | "owner";
}

interface DiscoveryAuthority {
  readonly principalId: string;
  readonly connectionId: string;
  readonly generation: number;
  readonly tokenVersion: number;
  readonly principalGeneration: number;
  readonly discoveryVersion: number;
}

function fail(
  code: LiveGoogleCalendarErrorCode,
  retryAfterSeconds?: number,
  detail?: string,
): never {
  throw new LiveGoogleCalendarError(code, retryAfterSeconds, detail);
}

function now(dependencies: LiveGoogleCalendarDependencies): number {
  const value = dependencies.nowEpochSeconds();
  if (!Number.isSafeInteger(value) || value < 0) return fail("internal");
  return value;
}

function authority(row: AuthorityRow): DiscoveryAuthority {
  if (
    row.status !== "active" ||
    !Number.isSafeInteger(row.generation) ||
    row.generation < 1 ||
    !Number.isSafeInteger(row.token_version) ||
    row.token_version < 1 ||
    !Number.isSafeInteger(row.discovery_version) ||
    row.discovery_version < 0 ||
    row.principal_generation !== row.generation
  )
    return fail("internal");
  return {
    principalId: canonicalUuid(row.principal_id) ?? fail("internal"),
    connectionId: canonicalUuid(row.id) ?? fail("internal"),
    generation: row.generation,
    tokenVersion: row.token_version,
    principalGeneration: row.principal_generation,
    discoveryVersion: row.discovery_version,
  };
}

function sameAuthority(left: DiscoveryAuthority, right: AuthorityRow): boolean {
  return (
    right.id === left.connectionId &&
    right.principal_id === left.principalId &&
    right.generation === left.generation &&
    right.principal_generation === left.principalGeneration
  );
}

function publicCalendar(row: CalendarRow): Calendar {
  const value = {
    id: canonicalUuid(row.id) ?? fail("internal"),
    connection_id: canonicalUuid(row.connection_id) ?? fail("internal"),
    name: row.name,
    description: row.description,
    can_write: row.access_role === "writer" || row.access_role === "owner",
    time_zone: row.time_zone,
    is_primary: row.is_primary === 1,
    is_selected: row.is_selected === 1,
    color: row.color,
  };
  if (row.is_primary !== 0 && row.is_primary !== 1) return fail("internal");
  if (row.is_selected !== 0 && row.is_selected !== 1) return fail("internal");
  return value;
}

export class LiveGoogleCalendar {
  readonly #dependencies: LiveGoogleCalendarDependencies;
  public constructor(dependencies: LiveGoogleCalendarDependencies) {
    if (dependencies.cursorKey.byteLength !== 32 || dependencies.eventIdKey.byteLength !== 32)
      throw new TypeError("live calendar keys must be exactly 32 bytes");
    this.#dependencies = dependencies;
  }

  public async listCalendars(authenticatedPrincipalId: string): Promise<CalendarList> {
    if (canonicalUuid(authenticatedPrincipalId) === undefined) fail("internal");
    const cached = await this.#discoveryRow(authenticatedPrincipalId);
    if (
      cached?.status === "active" &&
      cached.discovery_version > 0 &&
      cached.discovered_at !== null &&
      cached.discovered_at > cached.server_now - 300
    ) {
      return { calendars: await this.#readCalendars(authority(cached)) };
    }
    let snapshot: ConnectionSnapshot | null;
    try {
      snapshot = await this.#dependencies.accessTokens.loadForPrincipal(authenticatedPrincipalId);
    } catch (error) {
      return this.#tokenFailure(error);
    }
    if (snapshot === null) return { calendars: [] };
    let grant: AccessGrant;
    try {
      grant = await this.#dependencies.accessTokens.access(snapshot);
    } catch (error) {
      return this.#tokenFailure(error);
    }
    let current = await this.#discoveryRow(authenticatedPrincipalId);
    if (current?.status !== "active") return this.#staleDiscovery(current);
    const expected = authority(current);
    if (!this.#grantAuthorityMatches(grant, expected)) return fail("conflict");

    const owner = this.#owner();
    if (await this.#acquire(expected, owner)) {
      return this.#discoverAsOwner(expected, grant, owner, false);
    }
    let acquired = false;
    for (const delay of LOSER_DELAYS_MS) {
      current = await this.#discoveryRow(authenticatedPrincipalId);
      if (current === null || !sameAuthority(expected, current) || current.status !== "active")
        return this.#staleDiscovery(current);
      if (
        current.discovery_lease_owner === null &&
        current.discovery_version === expected.discoveryVersion + 1
      ) {
        return { calendars: await this.#readCalendars(expected) };
      }
      if (
        current.discovery_lease_owner === null ||
        (current.discovery_lease_until ?? 0) <= current.server_now
      ) {
        acquired = await this.#acquire(expected, owner);
        if (acquired) break;
      }
      try {
        await this.#dependencies.sleep(delay);
      } catch {
        return fail("internal");
      }
    }
    if (acquired) return this.#discoverAsOwner(expected, grant, owner, false);
    current = await this.#discoveryRow(authenticatedPrincipalId);
    if (current === null || !sameAuthority(expected, current) || current.status !== "active")
      return this.#staleDiscovery(current);
    if (
      current.discovery_lease_owner === null &&
      current.discovery_version === expected.discoveryVersion + 1
    )
      return { calendars: await this.#readCalendars(expected) };
    return fail("unavailable", RETRY_AFTER_SECONDS);
  }

  public async listEvents(
    authenticatedPrincipalId: string,
    publicCalendarId: string,
    query: EventsQuery,
  ): Promise<EventsResponse> {
    if (canonicalUuid(authenticatedPrincipalId) === undefined) fail("internal");
    if (canonicalUuid(publicCalendarId) === undefined) fail("internal");
    const resolved = await this.#eventGrant(authenticatedPrincipalId, publicCalendarId);
    if (resolved === null) return this.#absentGrant(authenticatedPrincipalId, publicCalendarId);
    const expected = authority(resolved);
    let pageToken: string | undefined;
    if (query.cursor !== undefined) {
      try {
        pageToken = await openEventCursor(
          query.cursor,
          this.#cursorBinding(expected, publicCalendarId, query),
          now(this.#dependencies),
          this.#dependencies.cursorKey,
        );
      } catch (error) {
        if (error instanceof CursorError) return fail("invalid_request");
        return fail("internal");
      }
    }
    const result = await this.#authorizedOperation(resolved, (grant) =>
      this.#eventsPage(grant, resolved.provider_calendar_id, query, pageToken),
    );
    if (!result.ok) return this.#eventProviderFailure(result.error);
    let events;
    try {
      events = await mapProviderEvents(result.value.items, {
        environment: this.#dependencies.environment,
        provider: "google",
        authorizationScopedCalendarId: publicCalendarId,
        eventIdKey: this.#dependencies.eventIdKey,
      });
    } catch (error) {
      if (error instanceof EventMappingError)
        return fail("unavailable", undefined, "event_mapping");
      return fail("internal");
    }
    let nextCursor: string | null = null;
    if (result.value.nextPageToken !== undefined) {
      try {
        nextCursor = await sealEventCursor(
          result.value.nextPageToken,
          this.#cursorBinding(expected, publicCalendarId, query),
          now(this.#dependencies),
          this.#dependencies.cursorKey,
          this.#dependencies.random,
        );
      } catch (error) {
        if (error instanceof CursorError) return fail("unavailable");
        return fail("internal");
      }
    }
    await this.#assertCalendarCurrent(resolved);
    return {
      events: [...events],
      next_cursor: nextCursor,
      omitted_count: result.value.omittedCount ?? 0,
    };
  }

  #eventBinding(calendarId: string) {
    return {
      environment: this.#dependencies.environment,
      provider: "google",
      authorizationScopedCalendarId: calendarId,
    } as const;
  }

  async #assertCalendarCurrent(expected: EventGrantRow): Promise<void> {
    const current = await this.#eventGrant(expected.principal_id, expected.calendar_id);
    if (current === null || !sameAuthority(authority(expected), current)) return fail("not_found");
  }

  async #assertCurrent(grant: AccessGrant): Promise<void> {
    try {
      await this.#dependencies.accessTokens.assertCurrent(grant);
    } catch (error) {
      if (error instanceof GoogleAccessTokenError && ["conflict", "reconnect"].includes(error.code))
        return fail("not_found");
      return this.#tokenFailure(error);
    }
  }

  async #authorizedOperation<T>(
    resolved: EventGrantRow,
    operation: (grant: AccessGrant) => Promise<ProviderOutcome<T>>,
  ): Promise<ProviderOutcome<T>> {
    const expected = authority(resolved);
    try {
      const snapshot = await this.#dependencies.accessTokens.loadForPrincipal(expected.principalId);
      if (snapshot === null || !this.#snapshotMatches(snapshot, expected)) return fail("not_found");
      let grant = await this.#dependencies.accessTokens.access(snapshot);
      if (!this.#grantAuthorityMatches(grant, expected)) return fail("not_found");
      await this.#assertCurrent(grant);
      let result = await operation(grant);
      if (!result.ok && result.error.code === "unauthorized") {
        const loaded = await this.#dependencies.accessTokens.loadForPrincipal(expected.principalId);
        if (loaded === null || !this.#snapshotMatches(loaded, expected)) return fail("not_found");
        grant = await this.#dependencies.accessTokens.access(loaded, { forceRefresh: true });
        if (!this.#grantAuthorityMatches(grant, expected)) return fail("not_found");
        await this.#assertCurrent(grant);
        result = await operation(grant);
      }
      await this.#assertCurrent(grant);
      return result;
    } catch (error) {
      return this.#tokenFailure(error);
    }
  }

  public async listChanges(
    principalId: string,
    calendarId: string,
    query: ChangesQuery,
  ): Promise<ChangesResponse> {
    const resolved = await this.#eventGrant(principalId, calendarId);
    if (resolved === null) return this.#absentGrant(principalId, calendarId);
    const binding = {
      principalId,
      connectionId: resolved.id,
      connectionGeneration: resolved.generation,
      calendarId,
    };
    let cursor: SyncCursorPayload = {};
    if (query.cursor !== undefined) {
      try {
        cursor = await openSyncCursor(query.cursor, binding, this.#dependencies.cursorKey);
      } catch {
        return fail("invalid_request");
      }
    }
    const result = await this.#authorizedOperation(resolved, (grant) =>
      listGoogleChangesPage({
        ...cursor,
        accessToken: grant.accessToken,
        calendarId: resolved.provider_calendar_id,
        configuration: this.#dependencies.googleProvider,
        fetch: this.#dependencies.fetch,
        ...(this.#dependencies.providerTimeoutMs === undefined
          ? {}
          : { timeoutMs: this.#dependencies.providerTimeoutMs }),
      }),
    );
    if (!result.ok) {
      if (result.error.code === "gone") return fail("sync_reset_required");
      return this.#eventProviderFailure(result.error);
    }
    const events = await mapProviderEvents(result.value.items, {
      ...this.#eventBinding(calendarId),
      eventIdKey: this.#dependencies.eventIdKey,
    });
    const next = result.value.nextPageToken;
    const sync = result.value.nextSyncToken;
    const nextCursor =
      next === undefined
        ? null
        : await sealSyncCursor(
            {
              ...(cursor.syncToken === undefined ? {} : { syncToken: cursor.syncToken }),
              pageToken: next,
            },
            binding,
            this.#dependencies.cursorKey,
            this.#dependencies.random,
          );
    const syncCursor =
      sync === undefined
        ? null
        : await sealSyncCursor(
            { syncToken: sync },
            binding,
            this.#dependencies.cursorKey,
            this.#dependencies.random,
          );
    await this.#assertCalendarCurrent(resolved);
    return {
      events: [...events],
      omitted_count: result.value.omittedCount ?? 0,
      next_cursor: nextCursor,
      sync_cursor: syncCursor,
    };
  }

  public async event(
    principalId: string,
    calendarId: string,
    method: GoogleEventRequest["method"],
    eventId?: string,
    body?: CreateEventRequest | PatchEventRequest,
    ifMatch?: string,
  ): Promise<CalendarEvent | undefined> {
    const resolved = await this.#eventGrant(principalId, calendarId);
    if (resolved === null) return this.#absentGrant(principalId, calendarId);
    const binding = this.#eventBinding(calendarId);
    let providerId: string;
    if (method === "POST") {
      providerId = await createProviderEventId(
        principalId,
        (body as CreateEventRequest).idempotency_key,
        binding,
        this.#dependencies.eventIdKey,
      );
    } else {
      try {
        providerId = await openEventId(eventId ?? "", binding, this.#dependencies.eventIdKey);
      } catch {
        return fail("not_found");
      }
    }
    if (method !== "GET" && resolved.access_role === "reader") return fail("permission_denied");
    const request = (
      operation: GoogleEventRequest["method"],
      payload?: Readonly<Record<string, unknown>>,
    ) =>
      this.#authorizedOperation(resolved, (grant) =>
        requestGoogleEvent({
          accessToken: grant.accessToken,
          calendarId: resolved.provider_calendar_id,
          eventId: providerId,
          method: operation,
          ...(payload === undefined ? {} : { body: payload }),
          ...(operation === "PATCH" || operation === "DELETE" ? { ifMatch: ifMatch ?? "" } : {}),
          configuration: this.#dependencies.googleProvider,
          fetch: this.#dependencies.fetch,
          ...(this.#dependencies.providerTimeoutMs === undefined
            ? {}
            : { timeoutMs: this.#dependencies.providerTimeoutMs }),
        }),
      );
    if ((method === "PATCH" || method === "DELETE") && !ifMatch) return fail("invalid_request");
    if (method === "PATCH") {
      const current = await request("GET");
      if (!current.ok) return this.#eventProviderFailure(current.error);
      if (current.value === undefined || current.value.status === "cancelled")
        return fail("not_found");
      if (body?.recurrence !== undefined && current.value.recurrence !== undefined)
        return fail("invalid_request");
      const start = body?.start ?? publicEventBoundary(current.value.start);
      const end = body?.end ?? publicEventBoundary(current.value.end);
      if (!boundariesOrdered(start, end)) return fail("invalid_request");
    }
    const payload =
      body === undefined
        ? undefined
        : providerWrite(body, method === "POST" ? providerId : undefined);
    let result = await request(method, payload);
    if (!result.ok && result.error.code === "invalid_request") return fail("invalid_request");
    if (method === "POST" && !result.ok && result.error.code === "duplicate") {
      result = await request("GET");
      if (!result.ok && (result.error.code === "gone" || result.error.code === "not_found"))
        return fail("conflict");
      if (result.ok && result.value?.status === "cancelled") return fail("conflict");
    }
    if (method === "DELETE" && !result.ok) {
      // Google answers a stale If-Match with 412 even when the event is already deleted.
      const gone = result.error.code === "precondition" ? await request("GET") : result;
      if (
        gone.ok
          ? gone.value?.status === "cancelled"
          : gone.error.code === "gone" || gone.error.code === "not_found"
      )
        return undefined;
    }
    if (!result.ok) return this.#eventProviderFailure(result.error);
    if (method === "DELETE") return undefined;
    if (result.value === undefined) return fail("unavailable");
    if (result.value.status === "cancelled") return fail("not_found");
    const [mapped] = await mapProviderEvents([result.value], {
      ...binding,
      eventIdKey: this.#dependencies.eventIdKey,
    });
    if (mapped === undefined) return fail("internal");
    await this.#assertCalendarCurrent(resolved);
    return mapped;
  }

  #cursorBinding(authority: DiscoveryAuthority, calendarId: string, query: EventsQuery) {
    return {
      principalId: authority.principalId,
      connectionId: authority.connectionId,
      connectionGeneration: authority.generation,
      calendarId,
      rangeStart: query.start,
      rangeEnd: query.end,
    } as const;
  }

  #owner(): string {
    try {
      return encodeBase64Url(randomBytes(this.#dependencies.random, 16));
    } catch {
      return fail("internal");
    }
  }

  #snapshotMatches(snapshot: ConnectionSnapshot, expected: DiscoveryAuthority): boolean {
    return (
      snapshot.principalId === expected.principalId &&
      snapshot.connectionId === expected.connectionId &&
      snapshot.generation === expected.generation &&
      snapshot.principalGeneration === expected.principalGeneration
    );
  }

  #grantAuthorityMatches(grant: AccessGrant, expected: DiscoveryAuthority): boolean {
    return (
      grant.principalId === expected.principalId &&
      grant.connectionId === expected.connectionId &&
      grant.generation === expected.generation &&
      grant.principalGeneration === expected.principalGeneration
    );
  }

  async #discoveryRow(principalId: string): Promise<DiscoveryRow | null> {
    try {
      return await this.#dependencies.db
        .prepare(
          `SELECT connection.id, connection.principal_id, connection.status, connection.generation,
                  connection.token_version,
                  principal.google_connection_generation AS principal_generation,
                  connection.discovery_lease_owner, connection.discovery_lease_until,
                  connection.discovery_version, unixepoch() AS server_now,
                  (SELECT MAX(calendar.updated_at) FROM calendars AS calendar
                   WHERE calendar.connection_id = connection.id) AS discovered_at
           FROM connections AS connection JOIN principals AS principal
             ON principal.id = connection.principal_id
           WHERE connection.principal_id = ? AND connection.provider = 'google' LIMIT 1`,
        )
        .bind(principalId)
        .first<DiscoveryRow>();
    } catch {
      return fail("internal");
    }
  }

  async #eventGrant(principalId: string, calendarId: string): Promise<EventGrantRow | null> {
    try {
      return await this.#dependencies.db
        .prepare(
          `SELECT connection.id, connection.principal_id, connection.status, connection.generation,
                  connection.token_version,
                  principal.google_connection_generation AS principal_generation,
                  connection.discovery_lease_owner, connection.discovery_lease_until,
                  connection.discovery_version, unixepoch() AS server_now,
                  calendar.id AS calendar_id,
                  calendar.provider_calendar_id, calendar.access_role
           FROM calendars AS calendar
           JOIN connections AS connection ON connection.id = calendar.connection_id
             AND connection.principal_id = calendar.principal_id
             AND connection.provider = 'google' AND connection.status = 'active'
           JOIN principals AS principal ON principal.id = connection.principal_id
             AND principal.google_connection_generation = connection.generation
           WHERE calendar.id = ? AND calendar.principal_id = ? LIMIT 1`,
        )
        .bind(calendarId, principalId)
        .first<EventGrantRow>();
    } catch {
      return fail("internal");
    }
  }

  /**
   * Why a request found no grant. The person's own calendar whose access lapsed says so; every
   * other absence, another principal's calendar included, reads as no such calendar.
   */
  async #absentGrant(principalId: string, calendarId: string): Promise<never> {
    let lapsed: unknown;
    try {
      lapsed = await this.#dependencies.db
        .prepare(
          `SELECT 1 FROM calendars AS calendar
           JOIN connections AS connection ON connection.id = calendar.connection_id
             AND connection.principal_id = calendar.principal_id
             AND connection.provider = 'google' AND connection.status = 'reconnect_required'
           JOIN principals AS principal ON principal.id = connection.principal_id
             AND principal.google_connection_generation = connection.generation
           WHERE calendar.id = ? AND calendar.principal_id = ? LIMIT 1`,
        )
        .bind(calendarId, principalId)
        .first();
    } catch {
      return fail("internal");
    }
    return lapsed === null ? fail("not_found") : fail("reconnect", undefined, "connection_lapsed");
  }

  async #acquire(expected: DiscoveryAuthority, owner: string): Promise<boolean> {
    const statement = this.#dependencies.db
      .prepare(
        `UPDATE connections SET discovery_lease_owner = ?,
           discovery_lease_until = MAX(unixepoch(), updated_at) + ?,
           discovery_lease_generation = generation, discovery_lease_token_version = token_version,
           updated_at = MAX(unixepoch(), updated_at)
         WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
           AND generation = ? AND token_version = ? AND discovery_version = ?
           AND (discovery_lease_owner IS NULL OR discovery_lease_until <= unixepoch())
           AND EXISTS (SELECT 1 FROM principals WHERE id = ?
             AND google_connection_generation = ?)
         RETURNING discovery_lease_owner`,
      )
      .bind(
        owner,
        LEASE_SECONDS,
        expected.connectionId,
        expected.principalId,
        expected.generation,
        expected.tokenVersion,
        expected.discoveryVersion,
        expected.principalId,
        expected.principalGeneration,
      );
    try {
      return (
        (await statement.first<{ discovery_lease_owner: string }>())?.discovery_lease_owner ===
        owner
      );
    } catch {
      const current = await this.#discoveryRow(expected.principalId);
      if (current === null || !sameAuthority(expected, current) || current.status !== "active")
        return this.#staleDiscovery(current);
      return (
        current.token_version === expected.tokenVersion &&
        current.discovery_version === expected.discoveryVersion &&
        current.discovery_lease_owner === owner &&
        current.discovery_lease_until !== null &&
        current.discovery_lease_until > current.server_now
      );
    }
  }

  async #discoverAsOwner(
    expected: DiscoveryAuthority,
    initialGrant: AccessGrant,
    owner: string,
    retriedUnauthorized: boolean,
    pageToken?: string,
    page = 1,
    found: readonly ProviderCalendar[] = [],
    omitted = 0,
  ): Promise<CalendarList> {
    let result;
    try {
      result = await listGoogleCalendarsPage({
        accessToken: initialGrant.accessToken,
        ...(pageToken === undefined ? {} : { pageToken }),
        configuration: this.#dependencies.googleProvider,
        fetch: this.#dependencies.fetch,
        ...(this.#dependencies.providerTimeoutMs === undefined
          ? {}
          : { timeoutMs: this.#dependencies.providerTimeoutMs }),
      });
    } catch {
      await this.#release(expected, owner);
      return fail("unavailable");
    }
    // A refused token restarts the whole list under the refreshed one.
    if (!result.ok && result.error.code === "unauthorized" && !retriedUnauthorized) {
      await this.#release(expected, owner);
      let refreshed: AccessGrant;
      try {
        const loaded = await this.#dependencies.accessTokens.loadForPrincipal(expected.principalId);
        if (loaded === null || !this.#snapshotMatches(loaded, expected)) return fail("conflict");
        refreshed = await this.#dependencies.accessTokens.access(loaded, { forceRefresh: true });
      } catch (error) {
        return this.#tokenFailure(error);
      }
      if (!this.#grantAuthorityMatches(refreshed, expected)) return fail("conflict");
      const current = await this.#discoveryRow(expected.principalId);
      if (current?.status !== "active" || !sameAuthority(expected, current))
        return this.#staleDiscovery(current);
      const advanced = authority(current);
      if (advanced.tokenVersion !== refreshed.tokenVersion) return fail("conflict");
      const nextOwner = this.#owner();
      if (!(await this.#acquire(advanced, nextOwner)))
        return fail("unavailable", RETRY_AFTER_SECONDS);
      return this.#discoverAsOwner(advanced, refreshed, nextOwner, true);
    }
    if (!result.ok) {
      await this.#release(expected, owner);
      return this.#discoveryProviderFailure(result.error);
    }
    const calendars = [...found, ...result.value.items];
    const omittedCount = omitted + (result.value.omittedCount ?? 0);
    const next = result.value.nextPageToken;
    // Mappings are replaced only by a list read to its end, or to the bound, under one lease.
    if (next !== undefined && page < MAX_DISCOVERY_PAGES)
      return this.#discoverAsOwner(
        expected,
        initialGrant,
        owner,
        retriedUnauthorized,
        next,
        page + 1,
        calendars,
        omittedCount,
      );
    return {
      calendars: await this.#commitDiscovery(expected, owner, calendars),
      discovery: { omittedCount, truncated: next !== undefined },
    };
  }

  async #release(expected: DiscoveryAuthority, owner: string): Promise<void> {
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE connections SET discovery_lease_owner = NULL, discovery_lease_until = NULL,
             discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
             updated_at = MAX(unixepoch(), updated_at)
           WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
             AND generation = ? AND token_version = ? AND discovery_version = ?
             AND discovery_lease_owner = ? AND discovery_lease_generation = ?
             AND discovery_lease_token_version = ?
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)`,
        )
        .bind(
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
          expected.discoveryVersion,
          owner,
          expected.generation,
          expected.tokenVersion,
          expected.principalId,
          expected.principalGeneration,
        )
        .run();
    } catch {
      // The exact bounded lease can safely expire; no broad cleanup is permitted.
    }
  }

  async #commitDiscovery(
    expected: DiscoveryAuthority,
    owner: string,
    calendars: readonly ProviderCalendar[],
  ): Promise<Calendar[]> {
    const ids = new Set<string>();
    const candidates: {
      id: string;
      providerId: string;
      name: string;
      description: string | null;
      timeZone: string | null;
      access: ProviderCalendar["access"];
      primary: number;
      selected: number;
      color: string | null;
    }[] = [];
    for (const calendar of calendars) {
      if (ids.has(calendar.id)) {
        await this.#release(expected, owner);
        return fail("unavailable");
      }
      ids.add(calendar.id);
      try {
        candidates.push({
          id: canonicalUuid(this.#dependencies.uuid()) ?? fail("internal"),
          providerId: calendar.id,
          name: calendar.name,
          description: calendar.description ?? null,
          timeZone: calendar.timeZone ?? null,
          access: calendar.access,
          primary: calendar.primary ? 1 : 0,
          selected: calendar.selected ? 1 : 0,
          color: calendar.color ?? null,
        });
      } catch {
        await this.#release(expected, owner);
        return fail("internal");
      }
    }
    const statements: D1PreparedStatement[] = [];
    // One statement per provider page keeps each bound value within D1's size limit.
    for (let offset = 0; offset < candidates.length; offset += PROVIDER_PAGE_SIZE) {
      statements.push(
        this.#dependencies.db
          .prepare(
            `WITH input AS (
               SELECT json_extract(value, '$.id') AS id,
                      json_extract(value, '$.providerId') AS provider_id,
                      json_extract(value, '$.name') AS name,
                      json_extract(value, '$.description') AS description,
                      json_extract(value, '$.timeZone') AS time_zone,
                      json_extract(value, '$.access') AS access_role,
                      json_extract(value, '$.primary') AS is_primary,
                      json_extract(value, '$.selected') AS is_selected,
                      json_extract(value, '$.color') AS color
               FROM json_each(?)
             )
             INSERT INTO calendars
               (id, principal_id, connection_id, provider_calendar_id, name, description,
                time_zone, access_role, is_primary, is_selected, color, discovered_at, updated_at)
             SELECT input.id, ?, ?, input.provider_id, input.name, input.description,
                    input.time_zone, input.access_role, input.is_primary, input.is_selected,
                    input.color, unixepoch(), unixepoch()
             FROM input
             WHERE EXISTS (SELECT 1 FROM connections AS connection JOIN principals AS principal
               ON principal.id = connection.principal_id
               WHERE connection.id = ? AND connection.principal_id = ?
                 AND connection.provider = 'google' AND connection.status = 'active'
                 AND connection.generation = ? AND connection.token_version = ?
                 AND connection.discovery_version = ?
                 AND connection.discovery_lease_owner = ?
                 AND connection.discovery_lease_generation = ?
                 AND connection.discovery_lease_token_version = ?
                 AND principal.google_connection_generation = ?)
             ON CONFLICT(connection_id, provider_calendar_id) DO UPDATE SET
               name = excluded.name, description = excluded.description,
               time_zone = excluded.time_zone, access_role = excluded.access_role,
               is_primary = excluded.is_primary, is_selected = excluded.is_selected,
               color = excluded.color, updated_at = MAX(unixepoch(), calendars.updated_at)
             WHERE calendars.principal_id = excluded.principal_id`,
          )
          .bind(
            JSON.stringify(candidates.slice(offset, offset + PROVIDER_PAGE_SIZE)),
            expected.principalId,
            expected.connectionId,
            expected.connectionId,
            expected.principalId,
            expected.generation,
            expected.tokenVersion,
            expected.discoveryVersion,
            owner,
            expected.generation,
            expected.tokenVersion,
            expected.principalGeneration,
          ),
      );
    }
    statements.push(
      this.#dependencies.db
        .prepare(
          `DELETE FROM calendars WHERE principal_id = ? AND connection_id = ?
             ${
               calendars.length === 0
                 ? ""
                 : "AND provider_calendar_id NOT IN (SELECT value FROM json_each(?))"
             }
             AND EXISTS (SELECT 1 FROM connections AS connection JOIN principals AS principal
               ON principal.id = connection.principal_id
               WHERE connection.id = ? AND connection.principal_id = ?
                 AND connection.provider = 'google' AND connection.status = 'active'
                 AND connection.generation = ? AND connection.token_version = ?
                 AND connection.discovery_version = ?
                 AND connection.discovery_lease_owner = ?
                 AND connection.discovery_lease_generation = ?
                 AND connection.discovery_lease_token_version = ?
                 AND principal.google_connection_generation = ?)`,
        )
        .bind(
          expected.principalId,
          expected.connectionId,
          ...(calendars.length === 0
            ? []
            : [JSON.stringify(calendars.map((calendar) => calendar.id))]),
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
          expected.discoveryVersion,
          owner,
          expected.generation,
          expected.tokenVersion,
          expected.principalGeneration,
        ),
    );
    statements.push(
      this.#dependencies.db
        .prepare(
          `UPDATE connections SET discovery_lease_owner = NULL, discovery_lease_until = NULL,
             discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
             discovery_version = discovery_version + 1,
             updated_at = MAX(unixepoch(), updated_at),
             last_provider_success_at = MAX(unixepoch(), updated_at)
           WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
             AND generation = ? AND token_version = ? AND discovery_version = ?
             AND discovery_lease_owner = ? AND discovery_lease_generation = ?
             AND discovery_lease_token_version = ?
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)`,
        )
        .bind(
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
          expected.discoveryVersion,
          owner,
          expected.generation,
          expected.tokenVersion,
          expected.principalId,
          expected.principalGeneration,
        ),
    );
    try {
      const results = await this.#dependencies.db.batch(statements);
      if (results.at(-1)?.meta.changes !== 1)
        return await this.#resolveAmbiguousCommit(expected, owner, statements);
    } catch {
      return await this.#resolveAmbiguousCommit(expected, owner, statements);
    }
    return this.#readCalendars(expected);
  }

  async #resolveAmbiguousCommit(
    expected: DiscoveryAuthority,
    owner: string,
    statements: D1PreparedStatement[],
  ): Promise<Calendar[]> {
    let current = await this.#discoveryRow(expected.principalId);
    if (
      current !== null &&
      sameAuthority(expected, current) &&
      current.status === "active" &&
      current.token_version === expected.tokenVersion &&
      current.discovery_version === expected.discoveryVersion &&
      current.discovery_lease_owner === owner
    ) {
      try {
        const results = await this.#dependencies.db.batch(statements);
        if (results.at(-1)?.meta.changes === 1) return await this.#readCalendars(expected);
      } catch {
        // One idempotent local retry only; the provider is never called again.
      }
      current = await this.#discoveryRow(expected.principalId);
    }
    if (
      current !== null &&
      sameAuthority(expected, current) &&
      current.status === "active" &&
      current.token_version === expected.tokenVersion &&
      current.discovery_lease_owner === null &&
      current.discovery_version === expected.discoveryVersion + 1
    )
      return this.#readCalendars(expected);
    return this.#staleDiscovery(current);
  }

  async #readCalendars(expected: DiscoveryAuthority): Promise<Calendar[]> {
    try {
      const result = await this.#dependencies.db
        .prepare(
          `SELECT calendar.id, calendar.connection_id, calendar.name, calendar.description,
                  calendar.access_role, calendar.time_zone, calendar.is_primary,
                  calendar.is_selected, calendar.color
           FROM calendars AS calendar JOIN connections AS connection
             ON connection.id = calendar.connection_id
             AND connection.principal_id = calendar.principal_id
           JOIN principals AS principal ON principal.id = connection.principal_id
           WHERE calendar.principal_id = ? AND calendar.connection_id = ?
             AND connection.provider = 'google' AND connection.status = 'active'
             AND connection.generation = ?
             AND principal.google_connection_generation = ?
           ORDER BY calendar.is_primary DESC, calendar.name, calendar.id`,
        )
        .bind(
          expected.principalId,
          expected.connectionId,
          expected.generation,
          expected.principalGeneration,
        )
        .all<CalendarRow>();
      const current = await this.#discoveryRow(expected.principalId);
      if (current === null || !sameAuthority(expected, current) || current.status !== "active")
        return this.#staleDiscovery(current);
      return result.results.map(publicCalendar);
    } catch (error) {
      if (error instanceof LiveGoogleCalendarError) throw error;
      return fail("internal");
    }
  }

  async #eventsPage(
    grant: AccessGrant,
    providerCalendarId: string,
    query: EventsQuery,
    pageToken: string | undefined,
  ) {
    try {
      return await listGoogleEventsPage({
        accessToken: grant.accessToken,
        calendarId: providerCalendarId,
        timeMin: query.start,
        timeMax: query.end,
        ...(pageToken === undefined ? {} : { pageToken }),
        configuration: this.#dependencies.googleProvider,
        fetch: this.#dependencies.fetch,
        ...(this.#dependencies.providerTimeoutMs === undefined
          ? {}
          : { timeoutMs: this.#dependencies.providerTimeoutMs }),
      });
    } catch {
      return fail("unavailable");
    }
  }

  #discoveryProviderFailure(error: ProviderError): never {
    const detail = `provider_${error.code}`;
    if (error.code === "permission_denied") return fail("conflict", undefined, detail);
    if (error.code === "rate_limited")
      return fail("rate", retryAfter(error) ?? RETRY_AFTER_SECONDS, detail);
    return fail("unavailable", retryAfter(error), detail);
  }

  #eventProviderFailure(error: ProviderError): never {
    const detail = `provider_${error.code}`;
    if (error.code === "precondition" || error.code === "duplicate")
      return fail("conflict", undefined, detail);
    if (error.code === "gone") return fail("not_found", undefined, detail);
    if (error.code === "permission_denied" || error.code === "not_found")
      return fail("not_found", undefined, detail);
    if (error.code === "rate_limited")
      return fail("rate", retryAfter(error) ?? RETRY_AFTER_SECONDS, detail);
    return fail("unavailable", retryAfter(error), detail);
  }

  #tokenFailure(error: unknown): never {
    if (error instanceof LiveGoogleCalendarError) throw error;
    if (error instanceof GoogleAccessTokenError) {
      const detail = `token_${error.code}`;
      if (error.code === "reconnect") return fail("reconnect", undefined, detail);
      if (error.code === "conflict") return fail("conflict", undefined, detail);
      if (error.code === "rate_limited") return fail("rate", error.retryAfterSeconds, detail);
      if (error.code === "unavailable") return fail("unavailable", error.retryAfterSeconds, detail);
    }
    return fail("internal");
  }

  #staleDiscovery(row: DiscoveryRow | null): never {
    if (row?.status === "reconnect_required") return fail("reconnect");
    return fail("conflict");
  }
}

function publicEventBoundary(boundary: ProviderEventBoundary) {
  return boundary.kind === "all_day"
    ? { kind: "date" as const, date: boundary.date }
    : {
        kind: "date_time" as const,
        date_time: boundary.dateTime,
        ...(boundary.timeZone === undefined ? {} : { time_zone: boundary.timeZone }),
      };
}

function boundariesOrdered(
  start: NonNullable<PatchEventRequest["start"]>,
  end: NonNullable<PatchEventRequest["end"]>,
): boolean {
  return start.kind === "date" && end.kind === "date"
    ? start.date <= end.date
    : start.kind === "date_time" &&
        end.kind === "date_time" &&
        Date.parse(start.date_time) <= Date.parse(end.date_time);
}

function providerWrite(
  body: CreateEventRequest | PatchEventRequest,
  id?: string,
): Readonly<Record<string, unknown>> {
  // Google merges nested PATCH objects, so changing boundary kind must null the other kind's fields.
  const boundary = (value: NonNullable<PatchEventRequest["start"]>) =>
    value.kind === "date"
      ? { date: value.date, ...(id === undefined ? { dateTime: null, timeZone: null } : {}) }
      : {
          dateTime: value.date_time,
          ...(value.time_zone === undefined ? {} : { timeZone: value.time_zone }),
          ...(id === undefined ? { date: null } : {}),
        };
  return {
    ...(id === undefined ? {} : { id }),
    ...(body.title === undefined ? {} : { summary: body.title }),
    ...(body.description === undefined ? {} : { description: body.description }),
    ...(body.location === undefined ? {} : { location: body.location }),
    ...(body.transparency === undefined ? {} : { transparency: body.transparency }),
    ...(body.recurrence === undefined ? {} : { recurrence: body.recurrence }),
    ...(body.start === undefined ? {} : { start: boundary(body.start) }),
    ...(body.end === undefined ? {} : { end: boundary(body.end) }),
  };
}
