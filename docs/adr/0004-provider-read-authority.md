# ADR 0004: Provider-read authority and refresh uncertainty

- Status: Accepted, amended by ADR 0005 (refresh leases, provider writes)
- Date: 2026-08-31

## Context

Google token refresh may rotate the refresh token. A Worker or D1 response can fail after Google has
accepted that side effect, so a retry cannot prove which refresh token remains authoritative.
Calendar discovery and event listing are read-only, but their results must not survive disconnect,
account deletion, replacement authorization, or tenant substitution.

## Decision

A refresh attempt holds a non-stealable 120-second D1 lease bound to the exact principal, connection
generation, and token version. D1 `unixepoch()` is the lease and token-expiry clock. The exact owner
may commit a returned envelope once. Other callers wait briefly for that version to advance. An
expired attempt transitions the connection to `reconnect_required`; the service never repeats an
uncertain refresh for the same token version.

Calendar discovery uses a separate 45-second D1 lease because repeating its bounded GET is safe.
Only one complete terminal page of at most 250 calendars atomically upserts stable opaque mappings,
deletes absent mappings, advances `discovery_version`, and releases the lease. Nonterminal,
malformed, stale, or unauthorized results cannot partially mutate mappings.

Event reads authorize the public calendar before opening an authenticated cursor and before token or
provider access. Cursors bind principal, connection generation, public calendar, exact range, and
the provider page token. Events are normalized and assigned keyed opaque identifiers in memory;
neither event bodies nor provider event identifiers are stored. The exact access grant is checked
again after the provider response before data is returned.

## Consequences

- A crash during refresh can require user reconnection even when Google completed the refresh. This
  is the deliberate fail-closed cost of avoiding credential-rotation corruption.
- Calendar discovery remains recoverable after a crashed reader because it has no provider-side
  mutation.
- Disconnect, deletion, refresh, and OAuth replacement clear stale discovery authority.
- Replacing `EVENT_ID_KEY_V1` still changes public event identifiers as described in ADR 0003.
- Persistent event caching, background synchronization, and provider writes remain out of scope.
