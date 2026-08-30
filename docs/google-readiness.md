# Google provider readiness checklist

Implementation and fake-provider tests may proceed without live credentials. An isolated LAB Worker
and empty D1 database are deployed for `https://tasknotes-calendar-lab.callumalpass.workers.dev`,
but its public trigger is disabled and Google client remains deliberately pending between acceptance
runs. Real Google testing is blocked until a human-controlled Google Cloud project provides:

- a Web application OAuth client dedicated to LAB;
- the exact callback URI
  `https://tasknotes-calendar-lab.callumalpass.workers.dev/oauth/google/callback`;
- OAuth consent branding, homepage, privacy policy, terms, and authorized domains;
- `openid email profile` for sign-in;
- an approved read-only Calendar scope for explicit connection;
- listed test users while the project remains in Testing;
- a client secret installed only through Wrangler secret storage.

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
