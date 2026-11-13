# ADR 0008: Event links, sessions that last while used, and tolerant calendar discovery

- Status: Accepted
- Date: 2026-11-13
- Amends: ADR 0001 (event shape, session lifetime, telemetry), ADR 0004 (calendar discovery), ADR
  0006 (cookie lifetime), ADR 0007 (links stay excluded)

## Context

Production use after ADR 0007 showed these faults:

- One calendar with an access role the service did not know failed the person's whole calendar list.
  So did a calendar with an unusable name, and any account with more than 250 calendars, which could
  never be listed.
- A recurring all-day event whose dates Google sends with a time zone was left out of every page.
- A session ended 90 days after sign-in however often it was used, so a person who opened TaskNotes
  every day still had to sign in and type a confirmation code four times a year.
- "Calendar access must be granted again" and every other conflict reached clients as the same 409
  `conflict`, so a client could not tell a person what to do.
- The request log recorded only the public error code. A 503 did not say whether Google timed out,
  refused the token, or returned something unreadable, and a successful page did not say how many
  events it had left out.
- An event carried no way to join its meeting or to open it in Google Calendar. ADR 0001 and ADR
  0007 excluded both links.

## Decision

### Event links

Every event carries two more read-only fields:

- `web_link` opens the event in Google Calendar. It is Google's `htmlLink`, and only when that is an
  https address on `www.google.com` or `calendar.google.com`.
- `conference_link` joins the event's video conference. It is the first `video` entry point of
  `conferenceData`, whoever provides the conference, and otherwise Google Meet's `hangoutLink`.

Both are `null` when absent. A link that is not https, carries a user name or password, or is longer
than 2,048 characters is unusable and reads as `null`; it never omits the event. The service asks
Google only for `htmlLink`, `hangoutLink` and `conferenceData(entryPoints(entryPointType,uri))`.
Dial-in numbers, access codes, PINs, the conference's name and its notes are not requested.

A link is calendar content. `web_link` contains Google's reference to the event, and
`conference_link` may contain a meeting passcode. Like titles, they are never stored or logged by
the service, and the API description tells clients the same. Links cannot be written: creating or
changing a conference stays out of the write contract.

Organizers, other attendees, and raw recurrence rules stay excluded.

### Sessions last while they are used

A session expires 30 days after its last recorded use. Use is recorded at most hourly, as before,
and each recording starts the 30 days again. The 90-day absolute lifetime is removed.

Revocation is unchanged and remains the way to end a session early: signing out, removing a device,
and deleting the account each end it at once. A session nobody uses still ends after 30 days.

`absolute_expires_at` leaves the public session shapes. The database column stays for now and is
written equal to the idle expiry, because the column is `NOT NULL` and the Worker before this ADR
reads it. Nothing reads it any more. A later migration drops it once no deployed Worker can read it.

A web session's cookie is issued with a `Max-Age` of the idle lifetime, and issued again on any
successful authenticated response whose use extended the session. Without that the browser would
drop the cookie 30 days after sign-in while the server still honoured it.

### A distinct error for lapsed access

`reconnect_required` is a new error code, sent with status 409. It means the person must grant
calendar access again. The calendar list returns it when the connection has lapsed, and so do event
reads and writes on the person's own calendar. `conflict` keeps every other meaning. A calendar that
belongs to someone else, or does not exist, still reads as 404.

### Tolerant calendar discovery

- A calendar the service cannot represent is left out of the list and counted, as an unusable event
  already is. That covers an unknown access role and an unusable name, description or time zone.
- Discovery follows the provider's pages to the end of the list, up to four pages and 1,000
  calendars. Mappings are still replaced atomically, once, under one lease, and only by a list read
  to its end or to that bound. A failure on any page leaves mappings as they were. The four provider
  timeouts fit inside the 45-second lease.
- Beyond 1,000 calendars the list is cut and the request log says so. A cut list is authoritative
  like any other, so calendars beyond the bound have no mapping.
- A left-out calendar likewise has no mapping. If it had one before, the mapping is deleted, and the
  calendar gets a new identifier if it later becomes representable.

### All-day dates with a time zone

A boundary with a `date` and no `dateTime` is an all-day boundary. An accompanying `timeZone` is
ignored: a date has no zone.

### Request log

The request log line gains two fields:

- `detail`: a stable code for the cause behind a failure, such as `provider_timeout`,
  `provider_invalid_response`, `token_reconnect` or `connection_lapsed`, or for a success that is
  knowingly incomplete, `calendar_list_truncated`.
- `omitted_count`: how many provider calendars or events a successful response left out.

Both are fixed vocabulary and counts. Neither is sent to the client, and neither contains anything a
person or the provider wrote.

## Consequences

- Clients can offer "Join" and "Open in Google Calendar". They must treat both links as private.
- The response contract is strict, so every event grows by two fields and the session shapes lose
  one. Clients that ignore unknown fields and do not read `absolute_expires_at` are unaffected; the
  TaskNotes client is such a client.
- A client that matched only on status keeps working: `reconnect_required` is still a 409.
- A stolen credential that is used at least every 30 days no longer expires by itself. Revocation
  from the device list and account deletion are the controls, as they were within the 90 days.
- The published privacy policy says sessions end "after 90 days at most". It must be changed before
  this Worker reaches production.
- No migration is needed, so rollback is a Worker rollback only. Under the previous Worker a session
  renewed by this one cannot be extended and ends at its current idle expiry, within 30 days.
- A calendar list can now succeed while missing a calendar. `omitted_count` in the request log is
  the only signal, by design: the list response has no count field.
