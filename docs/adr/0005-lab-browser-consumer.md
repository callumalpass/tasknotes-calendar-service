# ADR 0005: A single supervised LAB browser consumer

- Status: Accepted for LAB only
- Date: 2026-09-08

## Decision

Allow cross-origin browser access from exactly `https://lab.tasknotes-app.pages.dev` to the
canonical Calendar LAB Worker origin, only when `ENVIRONMENT` is `lab`. Preflight matches the
existing `/v1/` route and method definitions and accepts only Authorization and Content-Type
headers. Unknown origins, methods, headers, callbacks, and non-LAB environments fail closed. No
wildcard origin or cookie credential support is introduced. Requests without Origin retain the
existing native/CLI behavior. Canonical incoming origin checks still run before CORS; authentication
and principal-scoped authorization still run for actual API requests. Approved-origin error
responses are readable by the client. Preflights perform no authentication, database, or Google
work.

The TaskNotes client holds its opaque service credential and PKCE proof only in memory for
supervised acceptance. Provider credentials remain server-side. This is not a production browser
authentication or persistent session decision.

## Scope and removal condition

This names one concrete consumer and adds no general origin configuration or provider abstraction.
It does not enable the Worker public route or preview URLs. Remove or replace this narrow policy
when the LAB experiment is retired or a separately reviewed production browser/session design is
accepted. Remote browser acceptance must still prove popup, preflight, consent, and lifecycle
behavior.
