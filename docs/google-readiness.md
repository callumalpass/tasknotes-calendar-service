# Google provider readiness checklist

Implementation and fake-provider tests may proceed without live credentials. An isolated LAB Worker
and empty D1 database are deployed for `https://tasknotes-calendar-lab.callumalpass.workers.dev`,
but its public trigger is disabled between supervised acceptance runs. The Google Calendar API, LAB
Web OAuth client, consent configuration, listed test user, and Wrangler-held secret are configured
in the dedicated `tasknotes-calendar-lab` Google Cloud project. A supervised live-provider
acceptance run of the read slice passed on 2026-09-08:

- a Web application OAuth client dedicated to LAB;
- the exact callback URI
  `https://tasknotes-calendar-lab.callumalpass.workers.dev/oauth/google/callback`;
- OAuth consent branding, homepage, privacy policy, terms, and authorized domains;
- `openid email profile` for sign-in;
- the then read-only Calendar scope for explicit connection;
- listed test users while the project remains in Testing;
- a client secret installed only through Wrangler secret storage.

The run completed separate Google identity and Calendar grants, discovered live calendars, read and
normalized a bounded live event range, exercised concurrent stable identifiers, disconnected the
provider, deleted the account, and verified that only the keyed deletion fence remained. No event
contents or provider event identifiers were persisted. The LAB public and preview routes were then
disabled.

ADR 0005 replaced that scope with `calendar.events` (sensitive) and `calendar.calendarlist.readonly`
(non-sensitive), and both are on the LAB consent screen. A supervised run on 2026-11-06 passed
sign-in confirmation, connect over an old-scope grant, discovery and paged reads across 13 calendars
with nothing omitted, the change feed, event create, replay, patch, delete, conflict, boundary-kind
and cross-zone writes, recurring series edits, a second device reusing the grant, rate limiting,
disconnect, and account deletion. It left no test events.

Still unproven live: deleting one recurring instance with a current `etag`, Workspace `hd`
callbacks, and one unexplained `sync_reset_required` (410) from a change read after a burst of
edits, which did not recur when each edit was followed by a change read.

Before general availability, confirm from current Google documentation and the production console:

1. That `calendar.events` and `calendar.calendarlist.readonly` cover every shipped endpoint.
2. Sensitive/restricted classification of those scopes and any verification or assessment
   requirement.
3. Acceptance of one backend Web OAuth client serving TaskNotes web, Capacitor, and Obsidian front
   ends.
4. Production refresh-token behavior, quota headroom, Workspace restrictions, and provider
   revocation semantics.
5. Google API Services User Data Policy and Limited Use disclosures.

Never treat seven-day Testing-mode refresh-token expiry as production behavior. Never work around
provider verification by using a personal client registration in a public build.
