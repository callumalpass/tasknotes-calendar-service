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
proves possession of its verifier, confirms the identity when required, and receives a per-device
service credential.

The service identifies Google accounts by validated issuer and subject. Email may help the person
recognize the account but never determines ownership or merging.

## Event representation

The initial API overlays normalized external events in clients without writing them into TaskNotes
records. Preserve provider IDs as opaque server-side mapping material. Normalize all-day and timed
boundaries explicitly; do not silently invent timezone or recurrence semantics.

## Data lifecycle

Connection identity, encrypted tokens, device sessions, OAuth transactions, and revocation
generations are durable security state. Event responses begin as live bounded reads with a short
private read-through cache. Any later persistent cache remains disposable and is invalidated with
its dependent cursor.
