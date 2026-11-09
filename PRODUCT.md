# Product

TaskNotes Calendar Service gives TaskNotes clients one dependable, provider-neutral way to connect
external calendars without requiring users to create Google or Microsoft developer credentials.

It is shared by the TaskNotes web/native app and the Obsidian TaskNotes plugin. It is a TaskNotes
service, independent of mdbase product identity, subscriptions, entitlements, and collection
authorization.

## Initial outcome

A person can authorize Google once and, from any TaskNotes client authenticated as the same
immutable Google identity, list their calendars, read bounded or incremental event pages, and
create, update, or delete events. Google credentials remain encrypted in the service and never enter
TaskNotes clients or mdbase collections.

## Principles

1. **Provider identity without another password.** Use validated immutable provider identity. Email
   is display text only.
2. **One authority check.** Every object and provider operation is authorized from the current
   TaskNotes service principal before lookup or cache use.
3. **Provider data remains authoritative.** Reads and writes are live provider calls. Events are not
   mirrored or cached.
4. **Revocation wins.** Disconnect and deletion immediately invalidate sessions and dominate delayed
   work.
5. **Background work is explicit.** Webhooks, queues, cursors, and retries use versioned state
   machines and idempotent transitions.
6. **Failure stays contained.** Calendar outages never block TaskNotes task access or mdbase
   operations.
7. **Free does not mean unbounded.** Apply transparent range, rate, storage, and inactivity limits
   to preserve fair access.

## Non-goals

- Microsoft Calendar
- Writing TaskNotes tasks into external calendars, in the service or in any TaskNotes client
- Webhooks or background sync
- Storing task data or task-to-event mappings in the service
- Persistent full-calendar mirroring
- Writing external events into mdbase collections
- mdbase subscription-based entitlement
- Automatic merging of identities based on matching email addresses
