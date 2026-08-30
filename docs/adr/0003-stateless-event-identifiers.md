# ADR 0003: Stateless deterministic event identifiers

- Status: Accepted
- Date: 2026-09-01

## Decision

Public event and recurrence-series IDs are UUIDv8 values derived from HMAC-SHA-256. The structured
input binds a purpose and version, deployment environment, provider, authorization-scoped calendar
UUID, and opaque provider event or series ID. A dedicated 32-byte `EVENT_ID_KEY_V1` secret is used
only for this derivation. Raw provider IDs and the key are never returned, logged, or persisted as
an event mapping.

The key is intentionally non-rotating for the lifetime of an environment. There is no event mirror,
mapping table, cache, dual-key read path, or ID migration. Reads map live bounded provider pages and
produce the same IDs concurrently and across Worker instances.

## Consequences

This preserves a stateless read path and stable opaque IDs without retaining calendar content. It
also makes ordinary key rotation impossible without changing every public event and series ID.
Compromise requires replacing the key, accepting that identifier discontinuity, notifying clients,
and treating old IDs as obsolete. Environment and calendar binding contain accidental cross-scope
correlation; opaque IDs still convey no authority.
