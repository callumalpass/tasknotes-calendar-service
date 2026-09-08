# Google provider readiness checklist

Implementation and fake-provider tests may proceed without live credentials. An isolated LAB Worker
and empty D1 database are deployed for `https://tasknotes-calendar-lab.callumalpass.workers.dev`,
but its public trigger is disabled between supervised acceptance runs. The Google Calendar API, LAB
Web OAuth client, consent configuration, listed test user, and Wrangler-held secret are configured
in the dedicated `tasknotes-calendar-lab` Google Cloud project. A supervised live-provider
acceptance run passed on 2026-09-08:

- a Web application OAuth client dedicated to LAB;
- the exact callback URI
  `https://tasknotes-calendar-lab.callumalpass.workers.dev/oauth/google/callback`;
- OAuth consent branding, homepage, privacy policy, terms, and authorized domains;
- `openid email profile` for sign-in;
- an approved read-only Calendar scope for explicit connection;
- listed test users while the project remains in Testing;
- a client secret installed only through Wrangler secret storage.

The run completed separate Google identity and Calendar grants, discovered live calendars, read and
normalized a bounded live event range, exercised concurrent stable identifiers, disconnected the
provider, deleted the account, and verified that only the keyed deletion fence remained. No event
contents or provider event identifiers were persisted. The LAB public and preview routes were then
disabled.

Before general availability, confirm from current Google documentation and the production console:

1. Whether `calendar.readonly` or the narrower Calendar List + Events read-only pair covers every
   shipped endpoint.
2. Sensitive/restricted classification and any verification or assessment requirement.
3. Acceptance of one backend Web OAuth client serving TaskNotes web, Capacitor, and Obsidian front
   ends.
4. Production refresh-token behavior, quota headroom, Workspace restrictions, and provider
   revocation semantics.
5. Google API Services User Data Policy and Limited Use disclosures.

Never treat seven-day Testing-mode refresh-token expiry as production behavior. Never work around
provider verification by using a personal client registration in a public build.
