# ADR 0001: Service boundary and first vertical slice

- Status: Accepted, amended by ADR 0005 (provider writes, incremental reads, scopes)
- Date: 2026-08-30

## Decision

TaskNotes Calendar Service is an independent TaskNotes product service deployed on Cloudflare
Workers with D1. It has no mdbase identity, entitlement, billing, collection, or record-payload
dependency.

The first release is Google-only and read-only. It supports provider identity sign-in, explicit
Calendar connection, per-device TaskNotes sessions, encrypted server-side Google token custody,
calendar discovery, and one-calendar bounded event pages. Google remains authoritative. There are no
writes, task mappings, mdbase materialization, watch channels, incremental sync cursors, persistent
event mirror, Microsoft code, R2, Durable Objects, or generic provider registry.

Identity sign-in and Calendar authorization are separate transactions, although a client may present
them as a consecutive onboarding flow:

1. `sign_in` requests only `openid email profile`, validates identity, discards Google tokens, and
   issues a TaskNotes device session.
2. Authenticated `connect_calendar` requests `openid email profile` plus read-only Calendar access
   and offline access. It verifies that the returned immutable Google identity is the identity
   selected by the authenticated principal before storing an encrypted provider token envelope.

This separation prevents a second client from minting another Calendar refresh token merely to find
the existing principal, makes disconnect independent of device identity, and keeps future scope
changes explicit.

## Identity

A Google identity is keyed by `(provider, canonical issuer, subject)`. Supported Google issuer
spellings are explicitly validated and canonicalized to `https://accounts.google.com`. Email, name,
hosted domain, and Calendar owner addresses are display metadata only. Matching email strings never
merge identities.

The first slice permits one Google identity and one Google Calendar connection per principal.
Explicit multi-provider linking and principal merging are out of scope.

## Authorization and linking

The service uses a confidential Google Web OAuth client per environment. Google redirects only to
the Worker. Public TaskNotes clients never receive Google codes or tokens.

Each transaction has two independent PKCE boundaries:

- Worker-generated provider PKCE protects the Google code exchange. Its verifier is encrypted while
  the transaction is pending.
- Client-generated TaskNotes PKCE proves possession when redeeming the completed transaction for a
  service session.

State, OIDC nonce, polling capability, and both PKCE values are independently random. D1 stores
digests for state, nonce, and polling capability. Transaction IDs are locators, not authority.
Callback completion never returns credentials or personal data to the browser. Redemption is
one-time and atomic.

## Sessions

Device sessions use opaque 256-bit bearer credentials. D1 stores only a peppered SHA-256 digest.
Sessions have a 30-day idle and 90-day absolute lifetime and are independently revocable. Web cookie
transport remains a client-integration decision; raw bearer credentials must not be placed in
localStorage or URLs.

## Token custody

Provider token payloads are encrypted with a random per-envelope AES-256-GCM data key. The data key
is wrapped by a versioned AES-256-GCM key-encryption key. Associated data binds environment,
provider, principal, connection, token kind, and envelope schema. Unknown versions and
authentication failures fail closed. Writes use only the active key version. Rotation rewraps data
keys and cannot downgrade a newer token version.

## Read model and limits

Calendar reads use direct Google REST calls. Events are requested for exactly one server-owned
calendar UUID and one bounded range per request. Initial bounds are 93 days, 250 events, and one
provider page per Worker request. Continuation cursors are opaque, authenticated, expire after ten
minutes, and bind principal, connection generation, calendar, range, and provider page token.

Event pages are normalized directly from each bounded provider response. The first slice has no
event mirror, event mapping table, or event cache. Authenticated responses are `private, no-store`.

Event titles, descriptions, locations, attendee data, conference links, and raw provider responses
never enter telemetry. The first public event shape excludes attendees, organizers, conference
links, HTML links, and raw recurrence rules.

## Deletion and failure

Disconnect and account deletion remove local authority first. Provider revocation is best effort and
cannot preserve locally usable tokens or block local deletion. Principal and connection generations
make pre-revocation delayed work ineligible to commit.

Calendar service failure cannot block TaskNotes tasks or mdbase operations. The Obsidian plugin's
local/BYO mode remains a separate fallback.

## Consequences

The first-time experience has two logical Google grants and more explicit state, but repeated device
sign-in does not churn Calendar refresh tokens. The first slice intentionally does not deliver
background event updates; Queues and watch channels will be introduced only with a reachable
accepted synchronization design.
