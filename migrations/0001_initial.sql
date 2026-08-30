PRAGMA foreign_keys = ON;

CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('active', 'deleting')),
  generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at TEXT NOT NULL,
  last_active_at TEXT NOT NULL
) STRICT;

CREATE TABLE external_identities (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT,
  display_name TEXT,
  email_verified INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (provider, issuer, subject)
) STRICT;
CREATE INDEX external_identities_principal_idx ON external_identities(principal_id);

CREATE TABLE oauth_transactions (
  id TEXT PRIMARY KEY,
  intent TEXT NOT NULL CHECK (intent IN ('sign_in', 'connect_calendar', 'reconnect')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'authorized', 'failed', 'consumed', 'expired')),
  state_hash TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL,
  polling_secret_hash TEXT NOT NULL,
  tasknotes_pkce_challenge TEXT NOT NULL,
  provider_pkce_ciphertext TEXT NOT NULL,
  provider_pkce_iv TEXT NOT NULL,
  provider_pkce_key_version TEXT NOT NULL,
  authenticated_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  expected_identity_id TEXT REFERENCES external_identities(id) ON DELETE CASCADE,
  authorized_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  authorized_connection_id TEXT REFERENCES connections(id) ON DELETE CASCADE,
  device_name TEXT NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'ios', 'android', 'obsidian')),
  failure_code TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  callback_completed_at TEXT,
  consumed_at TEXT,
  CHECK (
    (status = 'failed' AND failure_code IS NOT NULL)
    OR (status != 'failed' AND failure_code IS NULL)
  )
) STRICT;
CREATE INDEX oauth_transactions_expiry_idx ON oauth_transactions(expires_at);

CREATE TABLE device_sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  credential_hash TEXT NOT NULL UNIQUE,
  device_name TEXT NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'ios', 'android', 'obsidian')),
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX device_sessions_principal_idx ON device_sessions(principal_id);
CREATE INDEX device_sessions_expiry_idx ON device_sessions(idle_expires_at, absolute_expires_at);

CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES external_identities(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  status TEXT NOT NULL CHECK (status IN ('active', 'reconnect_required', 'revoking')),
  generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
  granted_scopes TEXT NOT NULL,
  token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  wrapped_dek_iv TEXT NOT NULL,
  key_version TEXT NOT NULL,
  token_version INTEGER NOT NULL DEFAULT 1 CHECK (token_version > 0),
  refresh_lease_owner TEXT,
  refresh_lease_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_provider_success_at TEXT,
  UNIQUE (principal_id, provider)
) STRICT;
CREATE INDEX connections_identity_idx ON connections(identity_id);

CREATE TABLE calendars (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  provider_calendar_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  color TEXT,
  time_zone TEXT,
  access_role TEXT,
  is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
  etag TEXT,
  discovered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (connection_id, provider_calendar_id)
) STRICT;
CREATE INDEX calendars_connection_idx ON calendars(connection_id);

CREATE TABLE event_read_cache (
  cache_key TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  connection_generation INTEGER NOT NULL,
  calendar_id TEXT NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  range_start TEXT NOT NULL,
  range_end TEXT NOT NULL,
  cursor_fingerprint TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX event_read_cache_expiry_idx ON event_read_cache(expires_at);
CREATE INDEX event_read_cache_owner_idx ON event_read_cache(principal_id, connection_id, calendar_id);
