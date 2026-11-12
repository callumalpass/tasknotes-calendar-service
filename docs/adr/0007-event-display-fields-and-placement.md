# ADR 0007: Event display fields, calendar display data, and Worker placement

- Status: Accepted
- Date: 2026-11-13
- Amends: ADR 0001 (first public event shape, calendar metadata), ADR 0005 (read shape, rate limit)

## Context

With production sign-in open, the TaskNotes calendar showed three faults that the first event shape
could not fix on the client:

- A declined invitation looked the same as an accepted one.
- Google working-location entries and similar non-meetings were drawn as ordinary events.
- Every Google calendar had the same colour, and a calendar the person renamed kept its owner's
  name.

ADR 0001 excluded attendees from the first event shape. It also requested no event type, and
migration 0002 dropped the unused calendar colour column.

Measured from Melbourne on 2026-11-13, a request with no database query took about 40 ms and a
request with one took about 270 ms. Staging and production D1 are in eastern North America, the
Worker ran at the caller's nearest Cloudflare location, and an event read makes seven sequential
queries.

A month view over several calendars sends one request per calendar and page. Quick navigation could
pass the single 120-per-minute limit that signed-in requests shared with anonymous sign-in.

## Decision

### Event display fields

Every event carries three more read-only fields:

- `transparency`: `opaque` or `transparent`. It was already writable and already read from Google.
- `event_type`: `default`, `focus_time`, `out_of_office`, `working_location`, `birthday`, or
  `from_gmail`. A Google type outside that list reads as `default`, so a new provider type cannot
  hide or fail an event.
- `self_response`: `accepted`, `declined`, `tentative`, `needs_action`, or `null` when the signed-in
  person is not an attendee.

`self_response` narrows ADR 0001's exclusion of attendees; it does not lift it. Requests ask Google
for `attendees(self,responseStatus)` with `maxAttendees=1`. Google then returns at most one attendee
entry, the person's own whenever an event has more than one attendee, and of it only those two
properties. An event with a single attendee who is not the person yields that attendee's answer
without their identity; the service discards it. No attendee name, email, comment, or count is
requested, returned, or logged. Organizers, conference links, HTML links, and raw recurrence rules
stay excluded.

These fields are display metadata. A value the service cannot use reads as `default` or `null` and
does not omit the event. The write contract is unchanged: none of them can be set through the
service except `transparency`, as before.

### Calendar display data

- `name` is the person's own name for the calendar (`summaryOverride`) when they have set a usable
  one, otherwise the calendar's name.
- `is_selected` reports whether the person shows the calendar in Google Calendar. Clients may use it
  to choose a first selection.
- `color` is Google's background colour as lower-case `#rrggbb`, or `null` when Google gives no such
  value. Migration 0003 restores the column with that exact shape as a check constraint.
- Google's `writerWithoutPrivateAccess` role is a writer. It previously failed the whole calendar
  list.

Colour and selection are personal calendar metadata under the existing retention: until disconnect
or deletion, replaced at each discovery.

### Placement

Staging and production pin the Worker's `fetch` handler to `aws:us-east-1`, beside their databases.
A caller far from the database pays its distance once instead of once per query. LAB's database is
in Oceania beside its only users, so LAB is not pinned. Moving a database means moving the pin with
it.

A fresh access token is now answered from the database clock its snapshot was read under, which
removes one query from every event request. The authority rechecks around the provider call are
unchanged.

### Rate limits

There are two limiters. Anonymous sign-in stays at 120 requests a minute per address. Signed-in
requests get 300 a minute per principal, counted apart from sign-in. Google allows a person 600
Calendar queries a minute by default and a PATCH costs two, so 300 keeps one person inside that
allowance. Both fail closed.

## Consequences

- Clients can dim or hide declined invitations, treat working locations as something other than a
  meeting, and colour calendars as Google does. Clients decide the presentation.
- The response contract is strict, so every event and calendar response grows by these fields.
  Clients that ignore unknown fields are unaffected; the TaskNotes client does.
- Migration 0003 must be applied before the Worker that reads the columns is deployed. The previous
  Worker runs unchanged against the migrated schema, so rollback is a Worker rollback only. Existing
  calendar rows read as unselected and uncoloured until their next discovery, at most five minutes
  after their last one.
- A pinned Worker serves a caller near the database no faster than before, and a caller elsewhere no
  slower than one database round trip.
- With placement, one location counts every request, so the limits are close to exact rather than
  per location.
