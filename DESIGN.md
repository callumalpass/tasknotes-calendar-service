# Design

The service is an HTTP and background-work boundary, not a general SaaS dashboard. User-facing
linking pages should be quiet, direct, accessible, and consistent with TaskNotes: plain paper
surfaces, clear status language, no celebratory or promotional chrome.

## API character

- JSON APIs use one provider-neutral vocabulary.
- Errors have stable machine codes and short humane messages.
- Cross-tenant and nonexistent opaque resources are indistinguishable.
- Authenticated user data is never publicly cacheable.
- Provider implementation details are not exposed unless a user action depends on them.

## Linking experience

A client starts a short-lived, device-bound transaction and opens the system browser. Google returns
to the service. The callback browser never receives a service credential. The initiating client
proves possession of its verifier and, for sign-in, enters the one-time confirmation code shown only
in that browser, then receives a per-device service credential. Starting a connect supersedes the
person's abandoned attempt, so closing a browser never locks them out.

The service identifies Google accounts by validated issuer and subject. Email may help the person
recognize the account but never determines ownership or merging.

## Event representation

Clients overlay normalized external events without the service writing them into TaskNotes records.
Normalize all-day and timed boundaries explicitly; preserve all-day end dates as exclusive, and do
not silently invent timezone or recurrence semantics. `dateTime` is the authoritative instant and
`timeZone` is display metadata. Text is never silently truncated: an event outside the public
contract's bounds is omitted from its page and counted in `omitted_count`, so one unusual event
cannot fail a calendar. Public event and series identifiers are sealed, deterministic, and
reversible only under the environment's key and the authorization-resolved calendar, and they convey
no authority.

Events also report whether they block time, what kind of entry they are, and the signed-in person's
own answer to an invitation. These are display metadata: a value the service cannot use reads as the
plain default and never omits the event. Only the person's own attendee entry is ever asked of the
provider; no other attendee is read. Calendars report the person's own name for them, the provider's
colour, and whether the person shows them in the provider's interface. See ADR 0007.

Events carry a link that opens them in the provider's interface and a link that joins their video
conference. Both are calendar content: never stored, never logged, and `null` unless they are plain
https addresses without credentials. See ADR 0008.

## Provider writes

Writes are authorized like reads, rechecked immediately before the provider call, and never stored.
Creates carry a client `idempotency_key` that determines the Google event ID, so a retry cannot
duplicate. Updates and deletes require `If-Match` with the event's `etag`. Attendee notifications
stay off. A timed-out write has an unknown outcome: clients retry creates and re-read before
repeating anything else.

## Provider-read authority

Refresh attempts are serialized by a D1-clocked lease bound to the exact connection generation and
token version. The lease is stealable after expiry and every provider failure releases it, so a
crash or Google outage retries rather than forcing re-consent. If a rotated token was really lost,
the retry receives `invalid_grant` and reaches `reconnect_required`. Calendar discovery uses a
separately bounded, stealable lease. Only a Calendar List read to its end, or to the bound of 1,000
calendars, may atomically replace mappings and advance its discovery version. A calendar the service
cannot represent is left out and counted, so one unusual calendar cannot fail the list. See
ADR 0008.

Event cursors are opened only after principal-scoped calendar authorization and before any token or
provider operation. They authenticate the principal, connection generation, public calendar, read
shape, and private provider page or sync token. Provider results are released only after current
connection authority is rechecked.

## Data lifecycle

Connection identity, encrypted tokens, device sessions, OAuth transactions, revocation generations,
and opaque calendar mappings are durable security state. Event responses are live bounded provider
reads. There is no event mirror, event mapping table, or event cache; introducing any retained event
content requires a later accepted ADR. An hourly scheduled job deletes expired transactions, dead
sessions, and deletion fences older than any transaction they could still affect.
