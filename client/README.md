# @tasknotes/calendar-service-client

The client for the TaskNotes Calendar Service. TaskNotes front ends use it to sign a person in with
Google, list their calendars, and read and change their events, without holding a Google credential.

It is written for the TaskNotes app and the TaskNotes Obsidian plugin. The service accepts sign-in
only from those clients, so the package is of little use elsewhere.

## Install

```bash
npm install @tasknotes/calendar-service-client zod
```

`zod` is a peer dependency, version 3.25 or later, or any version 4.

## Use

The client runs wherever there is `fetch`, Web Crypto and `AbortController`. What differs between
hosts is passed in:

```ts
import { CalendarServiceClient } from "@tasknotes/calendar-service-client";

const client = new CalendarServiceClient({
  origin: "https://calendar.tasknotes.dev",
  storage: window.localStorage,
  host: {
    clientKind: "obsidian",
    deviceName: "Obsidian",
    credentials: {
      load: () => secrets.get("calendar-session"),
      save: (credential) => secrets.set("calendar-session", credential),
      clear: () => secrets.delete("calendar-session"),
    },
    openWindow: () => ({
      show: (url) => void window.open(url, "_blank"),
      close: () => undefined,
    }),
  },
});

client.subscribe(() => render(client.getSnapshot()));
await client.restore();
```

- `storage` holds what the client may lose: which calendars are shown and whether this device has
  signed in. It never holds a credential.
- `host.credentials` holds the session credential on hosts that sign in with a bearer session. Keep
  it where page script and other applications cannot read it. On the web it is `null`: the session
  is an `HttpOnly` cookie the client never sees.
- `host.openWindow` opens the window Google's consent page runs in. Call `signIn` and `connect` from
  the person's click, so the window is not blocked.
- `transport` replaces `fetch` on a host that has to send requests another way. It must reject with
  a `TypeError` when the service cannot be reached, and honour the request's signal.

### Signing in

`signIn()` opens Google's sign-in page. When the person has signed in there, the service shows them
an eight-character code and the snapshot's `awaitingCode` becomes true. Ask for the code and pass it
to `submitCode(code)`, or call `cancelAuthorization()`. A wrong code ends the attempt. `connect()`
then asks for calendar access, without a code.

### State

`getSnapshot()` returns the session, the Google connection, the calendars and the ones selected to
show, with `busy`, `awaitingCode` and `failure`. `subscribe(listener)` reports every change.

Sign-in, connection, refresh and account actions never reject. When one fails, the snapshot's
`failure` says why: `popup_blocked`, `code_rejected`, `authorization_expired`, `reconnect_required`,
`session_expired`, `rate_limited`, `unavailable` and so on. Show the person a message for it.

### Events

```ts
const { events, omitted } = await client.events(calendarId, start, end, signal);
const created = await client.createEvent(calendarId, fields, idempotencyKey);
const updated = await client.updateEvent(event, { title: "Renamed" });
await client.deleteEvent(event);
```

These reject with a `CalendarServiceError` whose `failure` is one of the codes above. A range may be
any length; the client reads it in the pieces the service allows. `omitted` counts events the
service could not represent and left out. Updates and deletions carry the event's `etag`, so a
change made elsewhere since the event was read fails with `conflict`. Read the event again and let
the person decide.

`createEvent` takes an idempotency key. Make one per event the person creates and reuse it when
retrying, so a retry cannot create the event twice.

`eventLinks(event)` returns the event's video-call link and its Google Calendar page after checking
both again. Treat them as private, like the event's title.

### Leaving

- `signOut()` ends this device's session.
- `disconnect()` withdraws the service's access to Google Calendar on every device.
- `deleteAccount()` deletes what the service holds about the person.
- `forget()` drops local state when the service cannot be reached to sign out.

## What the client never holds

Google access and refresh tokens stay in the service. The client holds a session with the service,
the calendar list, and the events of the ranges it was asked for, in memory only. It stores no
events.

## Versions

The package follows semantic versioning. Its version is separate from the service's. The service
keeps answering every published version that TaskNotes still ships.

## Licence

MIT
