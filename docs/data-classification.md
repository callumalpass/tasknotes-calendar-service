# Data classification and initial retention

| Data                             | Class               |                               Initial retention | Notes                                                                                                                                                                                                                                                                                |
| -------------------------------- | ------------------- | ----------------------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Google issuer and subject        | Identity-sensitive  |                          Until account deletion | Authoritative identity key; never a metric label                                                                                                                                                                                                                                     |
| Email and display name           | Personal            |                          Until account deletion | Display only; not authorization                                                                                                                                                                                                                                                      |
| Device session digest            | Credential verifier |       30 days after last use plus cleanup delay | Revoked or expired sessions are deleted hourly in batches of 100; raw credentials never persisted                                                                                                                                                                                    |
| OAuth transaction digests        | Security-sensitive  |           10 minutes plus bounded cleanup delay | Hourly deletion of up to 100 expired rows, including pending/exchanging; no raw secrets                                                                                                                                                                                              |
| Identity deletion fence digest   | Identity-sensitive  |               1 hour plus bounded cleanup delay | Keyed identity digest and deletion timestamp; hourly deletion of up to 100 fences older than 1 hour                                                                                                                                                                                  |
| Encrypted provider PKCE verifier | Secret ciphertext   |                            Transaction lifetime | Context-bound; deleted at terminal cleanup                                                                                                                                                                                                                                           |
| Google token envelope            | Secret ciphertext   | Until disconnect/deletion/reconnect replacement | Application-layer AEAD; no plaintext fallback                                                                                                                                                                                                                                        |
| Calendar metadata                | Personal            |          Until disconnect/deletion; refreshable | Name, description, time zone, role, colour, selection; raw provider calendar ID remains server-side                                                                                                                                                                                  |
| Live normalized event response   | Calendar content    |                                    Not retained | Includes event and conference links. No event mirror, mapping table, or cache                                                                                                                                                                                                        |
| Event ID derivation key          | Secret              |    Environment lifetime; non-rotating by design | Dedicated key; compromise replacement changes all event IDs                                                                                                                                                                                                                          |
| Request/audit metadata           | Operational         |         Workers Logs: 3 days Free / 7 days Paid | Request UUID, route name, method, status, duration, error code, Retry-After, a stable failure-cause code, a count of omitted provider items; internal errors log class and stable location only. No paths, principal/IP/provider IDs or payloads; automatic invocation logs disabled |

Retention values are implementation defaults, not permission to retain data in logs or backups.
Cloudflare Workers Logs retention is plan-dependent (3 days Free / 7 days Paid), and D1 Time Travel
can restore deleted rows for 7 days on Free and 30 days on Paid (both checked 2026-11-07). The
published privacy policy states the Paid figures, so it stays true on either plan.

Cleanup uses D1's clock. Without a backlog, eligible rows are removed at the next hourly run;
backlogs above 100 eligible rows per table take additional runs. There is no hard cleanup-delay
guarantee during backlog or scheduler failure. Deleting an expired OAuth transaction nulls a live
session's redemption reference, not the session. Fences only reject transactions created before the
deletion, whose 10-minute lifetime is below the 1-hour fence threshold. Accounts are never deleted
for inactivity.

`ALLOWED_ORIGINS` is an exact, comma-separated browser origin allow-list, empty by default in local
and LAB, and set per environment in `wrangler.jsonc` for staging and production. Native Obsidian
`requestUrl` bypasses browser CORS and needs no origin entry. WebView `fetch` does require its exact
origin (for example `app://obsidian.md`, `capacitor://app.tasknotes.dev`, or `http://localhost`) if
used; Capacitor's native HTTP transport avoids that requirement; patching ordinary `fetch` to use it
is disabled by default. Current Capacitor Android defaults to `https://localhost`, so configure the
actual client origin rather than assuming `http://localhost`. These origins are supported as
explicit configuration, not implicitly trusted defaults. Listed origins may use credentialed CORS,
which only the web session cookie of ADR 0006 needs; that cookie also requires a listed `Origin` on
every request.
