# ADR 0006: Web sessions use an HttpOnly cookie

- Status: Accepted
- Date: 2026-11-07
- Amends: ADR 0001 (web cookie transport decision)

## Context

ADR 0001 left web transport to client integration and forbade raw credentials in localStorage or
URLs. The web integration held its credential in memory, so every reload asked for Google sign-in
and a confirmation code again. A device session already lasts 30 idle and 90 absolute days, so the
browser needs somewhere to keep it that page script cannot read.

## Decision

A session's transport follows its `client_kind`, with no choice for the client and no overlap:

- `web` sessions authenticate only with the cookie. Redeeming one sets the cookie and leaves
  `credential` out of the body, so no script ever holds it.
- `ios`, `android`, and `obsidian` sessions authenticate only with `Authorization: Bearer`.

Presenting a session over the other transport is a 401. An `Authorization` header takes precedence
over a cookie, so a request never mixes the two.

### Cookie

`__Host-tasknotes_session`, set with `Path=/; Secure; HttpOnly; SameSite=Strict` and a `Max-Age` of
the absolute lifetime. The `__Host-` prefix binds it to the service host. The server still enforces
idle expiry, absolute expiry, and revocation on every request; the cookie conveys no authority of
its own. A header carrying more than one session cookie is rejected. ADR 0008 removes the absolute
lifetime: the cookie's `Max-Age` is the idle lifetime, and the cookie is issued again when a use
extends the session.

### Cross-site protection

- A cookie-authenticated request must carry an `Origin` in `ALLOWED_ORIGINS`, on every method.
  Otherwise it fails with 403 before the session is read. The web app is always cross-origin to the
  service, so its requests always carry `Origin`.
- `SameSite=Strict` is independent of that check, and also stops a cross-site page planting a
  session through a credentialed redeem.
- Redeeming a `web` transaction from an unlisted origin fails with 409 and leaves it redeemable.
- CORS sends `Access-Control-Allow-Credentials: true` for listed origins only, and never a wildcard.

### Deployment constraint

The cookie is only sent when the web origin and service are same-site, so production uses
`https://app.tasknotes.dev` with a service host under `tasknotes.dev`. A `workers.dev` service host
is cross-site to every web origin. LAB browser testing therefore goes through a same-origin
development proxy that sets `Origin`; it needs no weaker cookie attributes.

### Capacitor clients

The TaskNotes mobile app is the web app in a Capacitor WebView, and it is an `ios` or `android`
client, never `web`. Its origins are `capacitor://app.tasknotes.dev` on iOS and
`https://app.tasknotes.dev` on Android. The iOS origin is never same-site with the service, so both
platforms use one path: bearer on every request, with `credentials: "omit"`.

The app holds the credential sealed with AES-GCM under a non-extractable WebCrypto key in IndexedDB,
the same custody the mdbase SDK uses in this WebView. It never enters `localStorage`, a URL, or
React state. Script injection can use the session while the app is open but cannot extract the key.
The ciphertext and key share the app's sandbox, so this is not hardware-bound; Keychain or Keystore
custody would need a native plugin and can replace it without any service change.

Google refuses OAuth inside an embedded WebView, so native sign-in opens the system browser through
`@capacitor/browser`. The confirmation code is unchanged: it is typed back into the app, never
carried by a return URL.

### Revocation

Revocation and deletion remain server-side and take effect on the next request. Signing out the
current session or deleting the account also clears the cookie. Revoking another device does not.

## Consequences

- Sign-in survives reload and browser restart for the session's lifetime.
- Script injection in the web app can use the session while the page is open, but cannot extract it.
- Web `client_kind` sessions created before this ADR are rejected. Only LAB test sessions existed.
- Obsidian is unchanged. `ios` and `android` sessions gained their app-side custody above.
