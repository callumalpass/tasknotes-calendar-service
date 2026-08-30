import type { Calendar, EventsQuery, EventsResponse } from "../contracts";
import { UuidSchema } from "../contracts";
import {
  GoogleAccessTokenError,
  type AccessGrant,
  type ConnectionSnapshot,
  type GoogleAccessTokens,
} from "../connections/google-access-tokens";
import { encodeBase64Url } from "../crypto/base64url";
import { openEventCursor, sealEventCursor, CursorError } from "../crypto/cursor";
import { randomBytes, type RandomByteSource } from "../crypto/random";
import { mapProviderEvents, EventMappingError } from "../events/map-provider-events";
import {
  listGoogleCalendarsPage,
  listGoogleEventsPage,
  type GoogleProviderConfiguration,
} from "../provider/google";
import type { ProviderCalendar, ProviderError } from "../provider/types";

// Discovery is an idempotent GET, so an expired attempt may be stolen. The lease is longer than
// the configured provider timeout and uses D1's clock so Worker clock skew cannot create overlap.
const LEASE_SECONDS = 45;
const LOSER_DELAYS_MS = [50, 100, 200, 400, 800] as const;
const RETRY_AFTER_SECONDS = 1;
const MAX_RETRY_AFTER_SECONDS = 3_600;

export type LiveGoogleCalendarErrorCode =
  "invalid_request" | "not_found" | "reconnect" | "conflict" | "rate" | "unavailable" | "internal";

export class LiveGoogleCalendarError extends Error {
  public readonly code: LiveGoogleCalendarErrorCode;
  public readonly retryAfterSeconds?: number;

  public constructor(code: LiveGoogleCalendarErrorCode, retryAfterSeconds?: number) {
    super("Live calendar operation failed.");
    this.name = "LiveGoogleCalendarError";
    this.code = code;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
    Object.freeze(this);
  }
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

interface DiscoveryRow {
  readonly id: string;
  readonly principal_id: string;
  readonly status: "active" | "reconnect_required";
  readonly generation: number;
  readonly token_version: number;
  readonly principal_generation: number;
  readonly discovery_lease_owner: string | null;
  readonly discovery_lease_until: number | null;
  readonly last_provider_success_at: number | null;
  readonly discovery_version: number;
  readonly server_now: number;
}

interface CalendarRow {
  readonly id: string;
  readonly connection_id: string;
  readonly name: string;
  readonly description: string | null;
  readonly color: string | null;
  readonly time_zone: string | null;
  readonly is_primary: number;
}

interface EventGrantRow extends DiscoveryRow {
  readonly calendar_id: string;
  readonly provider_calendar_id: string;
}

interface DiscoveryAuthority {
  readonly principalId: string;
  readonly connectionId: string;
  readonly generation: number;
  readonly tokenVersion: number;
  readonly principalGeneration: number;
  readonly discoveryVersion: number;
}

function fail(code: LiveGoogleCalendarErrorCode, retryAfterSeconds?: number): never {
  throw new LiveGoogleCalendarError(code, retryAfterSeconds);
}

function retryAfter(error: ProviderError): number | undefined {
  const value = error.retryAfterSeconds;
  return value !== undefined && Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, MAX_RETRY_AFTER_SECONDS)
    : undefined;
}

function canonicalUuid(value: unknown): string {
  const parsed = UuidSchema.safeParse(value);
  if (!parsed.success || parsed.data !== value) return fail("internal");
  return parsed.data;
}

function now(dependencies: LiveGoogleCalendarDependencies): number {
  const value = dependencies.nowEpochSeconds();
  if (!Number.isSafeInteger(value) || value < 0) return fail("internal");
  return value;
}

function authority(row: DiscoveryRow): DiscoveryAuthority {
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
    principalId: canonicalUuid(row.principal_id),
    connectionId: canonicalUuid(row.id),
    generation: row.generation,
    tokenVersion: row.token_version,
    principalGeneration: row.principal_generation,
    discoveryVersion: row.discovery_version,
  };
}

function sameAuthority(left: DiscoveryAuthority, right: DiscoveryRow): boolean {
  return (
    right.id === left.connectionId &&
    right.principal_id === left.principalId &&
    right.generation === left.generation &&
    right.principal_generation === left.principalGeneration
  );
}

function publicCalendar(row: CalendarRow): Calendar {
  const value = {
    id: canonicalUuid(row.id),
    connection_id: canonicalUuid(row.connection_id),
    name: row.name,
    description: row.description,
    color: row.color,
    time_zone: row.time_zone,
    is_primary: row.is_primary === 1,
  };
  if (row.is_primary !== 0 && row.is_primary !== 1) return fail("internal");
  return value;
}

export class LiveGoogleCalendar {
  readonly #dependencies: LiveGoogleCalendarDependencies;
  readonly #discoveries = new Map<string, Promise<{ calendars: Calendar[] }>>();

  public constructor(dependencies: LiveGoogleCalendarDependencies) {
    if (dependencies.cursorKey.byteLength !== 32 || dependencies.eventIdKey.byteLength !== 32)
      throw new TypeError("live calendar keys must be exactly 32 bytes");
    this.#dependencies = dependencies;
  }

  public listCalendars(authenticatedPrincipalId: string): Promise<{ calendars: Calendar[] }> {
    canonicalUuid(authenticatedPrincipalId);
    const active = this.#discoveries.get(authenticatedPrincipalId);
    if (active !== undefined) return active;
    const discovery = this.#listCalendars(authenticatedPrincipalId).finally(() => {
      if (this.#discoveries.get(authenticatedPrincipalId) === discovery)
        this.#discoveries.delete(authenticatedPrincipalId);
    });
    this.#discoveries.set(authenticatedPrincipalId, discovery);
    return discovery;
  }

  async #listCalendars(authenticatedPrincipalId: string): Promise<{ calendars: Calendar[] }> {
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
    if (!this.#grantMatches(grant, expected)) return fail("conflict");

    for (;;) {
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
  }

  public async listEvents(
    authenticatedPrincipalId: string,
    publicCalendarId: string,
    query: EventsQuery,
  ): Promise<EventsResponse> {
    canonicalUuid(authenticatedPrincipalId);
    canonicalUuid(publicCalendarId);
    const resolved = await this.#eventGrant(authenticatedPrincipalId, publicCalendarId);
    if (resolved === null) return fail("not_found");
    const expected = authority(resolved);
    let snapshot: ConnectionSnapshot | null;
    let grant: AccessGrant;
    try {
      snapshot = await this.#dependencies.accessTokens.loadForPrincipal(authenticatedPrincipalId);
      if (snapshot === null || !this.#snapshotMatches(snapshot, expected)) return fail("not_found");
      grant = await this.#dependencies.accessTokens.access(snapshot);
    } catch (error) {
      if (error instanceof LiveGoogleCalendarError) throw error;
      if (error instanceof GoogleAccessTokenError && ["conflict", "reconnect"].includes(error.code))
        return fail("not_found");
      return this.#tokenFailure(error);
    }
    let pageToken: string | undefined;
    if (query.cursor !== undefined) {
      try {
        pageToken = await openEventCursor(
          query.cursor,
          this.#cursorBinding(grant, publicCalendarId, query),
          now(this.#dependencies),
          this.#dependencies.cursorKey,
        );
      } catch (error) {
        if (error instanceof CursorError) return fail("invalid_request");
        return fail("internal");
      }
    }
    let result = await this.#eventsPage(grant, resolved.provider_calendar_id, query, pageToken);
    if (!result.ok && result.error.code === "unauthorized") {
      try {
        grant = await this.#dependencies.accessTokens.access(snapshot, { forceRefresh: true });
      } catch (error) {
        return this.#tokenFailure(error);
      }
      if (!this.#grantAuthorityMatches(grant, expected)) return fail("not_found");
      result = await this.#eventsPage(grant, resolved.provider_calendar_id, query, pageToken);
    }
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
      if (error instanceof EventMappingError) return fail("unavailable");
      return fail("internal");
    }
    let nextCursor: string | null = null;
    if (result.value.nextPageToken !== undefined) {
      try {
        nextCursor = await sealEventCursor(
          result.value.nextPageToken,
          this.#cursorBinding(grant, publicCalendarId, query),
          now(this.#dependencies),
          this.#dependencies.cursorKey,
          this.#dependencies.random,
        );
      } catch (error) {
        if (error instanceof CursorError) return fail("unavailable");
        return fail("internal");
      }
    }
    try {
      await this.#dependencies.accessTokens.assertCurrent(grant);
    } catch (error) {
      if (error instanceof GoogleAccessTokenError && ["conflict", "reconnect"].includes(error.code))
        return fail("not_found");
      return this.#tokenFailure(error);
    }
    return { events: [...events], next_cursor: nextCursor };
  }

  #cursorBinding(grant: AccessGrant, calendarId: string, query: EventsQuery) {
    return {
      principalId: grant.principalId,
      connectionId: grant.connectionId,
      connectionGeneration: grant.generation,
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

  #grantMatches(grant: AccessGrant, expected: DiscoveryAuthority): boolean {
    return (
      this.#grantAuthorityMatches(grant, expected) && grant.tokenVersion === expected.tokenVersion
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
                  connection.last_provider_success_at, connection.discovery_version,
                  unixepoch() AS server_now
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
                  connection.last_provider_success_at, connection.discovery_version,
                  unixepoch() AS server_now, calendar.id AS calendar_id,
                  calendar.provider_calendar_id
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
        current.token_version === expected.tokenVersion && current.discovery_lease_owner === owner
      );
    }
  }

  async #discoverAsOwner(
    expected: DiscoveryAuthority,
    initialGrant: AccessGrant,
    owner: string,
    retriedUnauthorized: boolean,
  ): Promise<{ calendars: Calendar[] }> {
    let result;
    try {
      result = await listGoogleCalendarsPage({
        accessToken: initialGrant.accessToken,
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
    if (result.value.nextPageToken !== undefined) {
      await this.#release(expected, owner);
      return fail("conflict");
    }
    return { calendars: await this.#commitDiscovery(expected, owner, result.value.items) };
  }

  async #release(expected: DiscoveryAuthority, owner: string): Promise<void> {
    try {
      await this.#dependencies.db
        .prepare(
          `UPDATE connections SET discovery_lease_owner = NULL, discovery_lease_until = NULL,
             discovery_lease_generation = NULL, discovery_lease_token_version = NULL,
             updated_at = MAX(unixepoch(), updated_at)
           WHERE id = ? AND principal_id = ? AND provider = 'google' AND status = 'active'
             AND generation = ? AND token_version = ? AND discovery_lease_owner = ?
             AND discovery_lease_generation = ? AND discovery_lease_token_version = ?
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)`,
        )
        .bind(
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
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
    const timestamp = now(this.#dependencies);
    const ids = new Set<string>();
    const statements: D1PreparedStatement[] = [];
    for (const calendar of calendars) {
      if (ids.has(calendar.id)) {
        await this.#release(expected, owner);
        return fail("unavailable");
      }
      ids.add(calendar.id);
      let candidate: string;
      try {
        candidate = canonicalUuid(this.#dependencies.uuid());
      } catch {
        await this.#release(expected, owner);
        return fail("internal");
      }
      statements.push(
        this.#dependencies.db
          .prepare(
            `INSERT INTO calendars
               (id, principal_id, connection_id, provider_calendar_id, name, description, color,
                time_zone, access_role, is_primary, etag, discovered_at, updated_at)
             SELECT ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?
             WHERE EXISTS (SELECT 1 FROM connections AS connection JOIN principals AS principal
               ON principal.id = connection.principal_id
               WHERE connection.id = ? AND connection.principal_id = ?
                 AND connection.provider = 'google' AND connection.status = 'active'
                 AND connection.generation = ? AND connection.token_version = ?
                 AND connection.discovery_lease_owner = ?
                 AND connection.discovery_lease_generation = ?
                 AND connection.discovery_lease_token_version = ?
                 AND principal.google_connection_generation = ?)
             ON CONFLICT(connection_id, provider_calendar_id) DO UPDATE SET
               name = excluded.name, description = excluded.description, color = NULL,
               time_zone = excluded.time_zone, access_role = excluded.access_role,
               is_primary = excluded.is_primary, etag = NULL, updated_at = excluded.updated_at
             WHERE calendars.principal_id = excluded.principal_id`,
          )
          .bind(
            candidate,
            expected.principalId,
            expected.connectionId,
            calendar.id,
            calendar.name,
            calendar.description ?? null,
            calendar.timeZone ?? null,
            calendar.access,
            calendar.primary ? 1 : 0,
            timestamp,
            timestamp,
            expected.connectionId,
            expected.principalId,
            expected.generation,
            expected.tokenVersion,
            owner,
            expected.generation,
            expected.tokenVersion,
            expected.principalGeneration,
          ),
      );
    }
    const placeholders = calendars.map(() => "?").join(", ");
    statements.push(
      this.#dependencies.db
        .prepare(
          `DELETE FROM calendars WHERE principal_id = ? AND connection_id = ?
             ${calendars.length === 0 ? "" : `AND provider_calendar_id NOT IN (${placeholders})`}
             AND EXISTS (SELECT 1 FROM connections AS connection JOIN principals AS principal
               ON principal.id = connection.principal_id
               WHERE connection.id = ? AND connection.principal_id = ?
                 AND connection.provider = 'google' AND connection.status = 'active'
                 AND connection.generation = ? AND connection.token_version = ?
                 AND connection.discovery_lease_owner = ?
                 AND connection.discovery_lease_generation = ?
                 AND connection.discovery_lease_token_version = ?
                 AND principal.google_connection_generation = ?)`,
        )
        .bind(
          expected.principalId,
          expected.connectionId,
          ...calendars.map((calendar) => calendar.id),
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
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
             AND generation = ? AND token_version = ? AND discovery_lease_owner = ?
             AND discovery_lease_generation = ? AND discovery_lease_token_version = ?
             AND EXISTS (SELECT 1 FROM principals WHERE id = ?
               AND google_connection_generation = ?)`,
        )
        .bind(
          expected.connectionId,
          expected.principalId,
          expected.generation,
          expected.tokenVersion,
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
                  calendar.color, calendar.time_zone, calendar.is_primary
           FROM calendars AS calendar JOIN connections AS connection
             ON connection.id = calendar.connection_id
             AND connection.principal_id = calendar.principal_id
           JOIN principals AS principal ON principal.id = connection.principal_id
           WHERE calendar.principal_id = ? AND calendar.connection_id = ?
             AND connection.provider = 'google' AND connection.status = 'active'
             AND connection.generation = ? AND connection.token_version = ?
             AND principal.google_connection_generation = ?
           ORDER BY calendar.is_primary DESC, calendar.name, calendar.id`,
        )
        .bind(
          expected.principalId,
          expected.connectionId,
          expected.generation,
          expected.tokenVersion,
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
    if (error.code === "permission_denied") return fail("conflict");
    if (error.code === "rate_limited")
      return fail("rate", retryAfter(error) ?? RETRY_AFTER_SECONDS);
    return fail("unavailable", retryAfter(error));
  }

  #eventProviderFailure(error: ProviderError): never {
    if (error.code === "permission_denied" || error.code === "not_found") return fail("not_found");
    if (error.code === "rate_limited")
      return fail("rate", retryAfter(error) ?? RETRY_AFTER_SECONDS);
    return fail("unavailable", retryAfter(error));
  }

  #tokenFailure(error: unknown): never {
    if (error instanceof LiveGoogleCalendarError) throw error;
    if (error instanceof GoogleAccessTokenError) {
      if (error.code === "reconnect") return fail("reconnect");
      if (error.code === "conflict") return fail("conflict");
      if (error.code === "rate_limited") return fail("rate", error.retryAfterSeconds);
      if (error.code === "unavailable") return fail("unavailable", error.retryAfterSeconds);
    }
    return fail("internal");
  }

  #staleDiscovery(row: DiscoveryRow | null): never {
    if (row?.status === "reconnect_required") return fail("reconnect");
    return fail("conflict");
  }
}
