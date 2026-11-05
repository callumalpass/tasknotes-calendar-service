# ADR 0005: Stateless provider writes and incremental reads

- Status: Accepted
- Date: 2026-11-06
- Supersedes: ADR 0003
- Amends: ADR 0001 (read-only scope, one-provider-page rule retained), ADR 0004 (refresh leases)

## Context

The read-only slice offers little over an ICS subscription, while the Obsidian plugin's
bring-your-own-credentials mode already writes events and syncs incrementally. The service justifies
its token custody only if it gives every TaskNotes client the same no-setup Calendar capability.
Clients own task-to-event mapping and sync logic. The service must not need task data, so it stays
independent of mdbase and keeps no event mirror.

Live review also showed that strict event validation turned ordinary Google variation into outages,
and that ordinary abandonment and transient failure paths ended in lockout or forced re-consent.

## Decision: stateless write proxy

The service remains Google-only, on Workers and D1, with no queues, webhooks, event storage, or
mapping table. It adds create, read-one, update, delete, and incremental change reads.

### Scopes

`connect_calendar` requests `calendar.events` and `calendar.calendarlist.readonly` instead of
`calendar.readonly`. There is one scope set; no read-only connection tier exists. No production
connection exists, so there is no scope migration. LAB connections reconnect.

### Event identifiers

Public event and series IDs become a deterministic, reversible sealed form, replacing the one-way
HMAC UUID. One mechanism serves reads and writes; there is no second handle field.

- `EVENT_ID_KEY_V1` is split by HKDF-SHA-256 into a MAC subkey and an AES-256-GCM subkey.
- Associated data is the same tuple ADR 0003 bound: purpose, version, environment, provider, and
  authorization-resolved calendar UUID.
- The 96-bit IV is the truncated HMAC-SHA-256 of that tuple and the provider ID, so equal input
  gives an equal public ID across Workers and no per-ID state exists.
- The public form is `e1_` plus base64url. Provider event IDs longer than 1024 bytes are treated as
  unmappable events.

Authentication failure on open is `resource_not_found`, indistinguishable from an unknown ID. A
valid ID conveys no authority: the calendar is resolved under the principal first, and the ID opens
only under that calendar's UUID. The key stays non-rotating, as in ADR 0003. Reconnecting keeps
calendar UUIDs and so keeps IDs; disconnecting deletes them, and clients must relink.

### Write contract

- `POST /v1/calendars/{calendar_id}/events` takes a client-generated `idempotency_key` UUID. The
  Google event ID is a keyed base32hex derivation of principal, calendar, and that key, so a retry
  cannot duplicate. A provider 409 is resolved by reading the event: a live event is returned as the
  original success, a cancelled one is `conflict`.
- `GET /v1/calendars/{calendar_id}/events/{event_id}` reads one event.
- `PATCH` and `DELETE` on that path require `If-Match` with the event `etag` from the service. A
  provider 412 is `conflict`. `DELETE` of an already gone event succeeds.
- An instance ID addresses one instance and a series ID addresses the series. There is no scope
  parameter.
- Writable fields are title, description, location, start, end, transparency, and for creation or
  series updates bounded `recurrence` RRULE, EXDATE, and RDATE lines. Attendee notifications stay
  off (`sendUpdates=none`).
- Calendars report `can_write`. A write to a read-only calendar is `permission_denied` before any
  token or provider work.

A write is authorized exactly like a read, then connection authority is rechecked immediately before
the provider call. A provider 401 refreshes and retries once because the write did not apply. A
timeout is reported as `dependency_unavailable`; only creates are safely retried by clients without
re-reading, through the idempotency key. In-flight writes cannot be recalled by a concurrent
revocation: revocation dominates work that has not yet reached Google.

### Reads

- Range reads no longer request deleted events. Stateless overlays have no use for tombstones.
- `GET /v1/calendars/{calendar_id}/changes` passes Google sync tokens through an authenticated
  cursor bound to principal, connection generation, and calendar. An expired sync token is
  `sync_reset_required` (410) and the client restarts. Change reads return tombstones, which may
  carry only an ID.
- One unmappable event no longer fails a page. Pages omit it and report `omitted_count`. Text is
  still never truncated. Whole-response failures remain failures.
- `dateTime` is the authoritative instant. `timeZone` is display metadata and need not match the
  offset of `dateTime`. An unknown zone is dropped, not fatal. Zero-duration events are valid.
- Unknown callback query parameters from Google are ignored rather than rejected: the callback
  authenticates through `state`, so its metadata is not an input.

## Decision: ordinary failure paths

- Refresh leases become stealable after expiry, like discovery leases, and every provider failure
  releases the lease. If Google really did rotate a token and the response was lost, the retry
  receives `invalid_grant` and reaches `reconnect_required`, the same end state ADR 0004 forced on
  every crash. This replaces the expired-lease transition rather than adding to it.
- `assertCurrent` checks principal, connection, and generation. A benign token refresh is not a
  conflict.
- A concurrent session usage update is not an authentication failure.
- Starting a connect supersedes the principal's stale or pending transaction. An `exchanging`
  transaction within its deadline still conflicts.
- Scheduled cleanup deletes expired transactions, dead sessions, and deletion fences older than any
  transaction they could still affect.

## Decision: sign-in confirmation

Sign-in redemption requires a one-time confirmation code shown only in the browser that completed
Google consent. This binds the approving person to the initiating client. An attacker who sends a
victim a real authorization link holds the polling secret and verifier but not the code. The code is
stored as a digest, one wrong attempt fails the transaction, and sign-in uses
`prompt=select_account`. Connect does not need it, because it already binds the expected Google
subject to an authenticated principal.

## Consequences

- `calendar.events` needs Google verification review before general availability.
- Clients must handle `sync_reset_required`, `conflict` on stale etags, and `omitted_count`.
- Public IDs are longer, opaque strings rather than UUIDs.
- All sync still requires a running client. Server-side sync, webhooks, and mdbase materialization
  remain out of scope and need their own ADR.
