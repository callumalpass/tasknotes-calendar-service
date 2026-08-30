PRAGMA foreign_keys = ON;

CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at)
) STRICT;

CREATE TABLE external_identities (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  issuer TEXT NOT NULL CHECK (issuer = 'https://accounts.google.com'),
  subject TEXT NOT NULL,
  email TEXT,
  display_name TEXT,
  email_verified INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  UNIQUE (provider, issuer, subject),
  UNIQUE (principal_id),
  UNIQUE (principal_id, id)
) STRICT;

CREATE TABLE identity_deletion_fences (
  identity_digest TEXT PRIMARY KEY,
  deleted_at INTEGER NOT NULL CHECK (deleted_at >= 0)
) STRICT;

CREATE TABLE device_sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  credential_hash TEXT NOT NULL UNIQUE,
  device_name TEXT NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'ios', 'android', 'obsidian')),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  last_used_at INTEGER NOT NULL CHECK (last_used_at >= created_at),
  idle_expires_at INTEGER NOT NULL CHECK (idle_expires_at > last_used_at),
  absolute_expires_at INTEGER NOT NULL CHECK (absolute_expires_at >= idle_expires_at),
  revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;
CREATE INDEX device_sessions_principal_idx ON device_sessions(principal_id);
CREATE INDEX device_sessions_expiry_idx ON device_sessions(idle_expires_at, absolute_expires_at);

CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  status TEXT NOT NULL CHECK (status IN ('active', 'reconnect_required')),
  generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
  envelope_schema_version INTEGER NOT NULL CHECK (envelope_schema_version = 1),
  key_version INTEGER NOT NULL CHECK (key_version > 0),
  dek_iv TEXT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  payload_iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  token_version INTEGER NOT NULL DEFAULT 1 CHECK (token_version > 0),
  refresh_lease_owner TEXT,
  refresh_lease_until INTEGER,
  refresh_lease_generation INTEGER,
  refresh_lease_token_version INTEGER,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  last_provider_success_at INTEGER CHECK (
    last_provider_success_at IS NULL OR last_provider_success_at >= created_at
  ),
  FOREIGN KEY (principal_id, identity_id)
    REFERENCES external_identities(principal_id, id) ON DELETE CASCADE,
  UNIQUE (principal_id, provider),
  UNIQUE (principal_id, id),
  CHECK (
    (refresh_lease_owner IS NULL
      AND refresh_lease_until IS NULL
      AND refresh_lease_generation IS NULL
      AND refresh_lease_token_version IS NULL)
    OR
    (refresh_lease_owner IS NOT NULL
      AND refresh_lease_until IS NOT NULL
      AND refresh_lease_generation IS NOT NULL
      AND refresh_lease_token_version IS NOT NULL
      AND length(refresh_lease_owner) BETWEEN 1 AND 256
      AND refresh_lease_until >= 0
      AND refresh_lease_generation = generation
      AND refresh_lease_token_version = token_version)
  )
) STRICT;

CREATE TRIGGER connections_prevent_version_rollback
BEFORE UPDATE OF generation, token_version ON connections
FOR EACH ROW
WHEN NEW.generation < OLD.generation OR NEW.token_version < OLD.token_version
BEGIN
  SELECT RAISE(ABORT, 'connection version rollback');
END;

CREATE TRIGGER connections_immutable_ownership
BEFORE UPDATE OF id, principal_id, identity_id, provider ON connections
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'connection ownership is immutable');
END;

CREATE TABLE calendars (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  provider_calendar_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  color TEXT,
  time_zone TEXT,
  access_role TEXT,
  is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
  etag TEXT,
  discovered_at INTEGER NOT NULL CHECK (discovered_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= discovered_at),
  FOREIGN KEY (principal_id, connection_id)
    REFERENCES connections(principal_id, id) ON DELETE CASCADE,
  UNIQUE (connection_id, provider_calendar_id),
  UNIQUE (principal_id, id)
) STRICT;
CREATE INDEX calendars_connection_idx ON calendars(principal_id, connection_id);

CREATE TABLE oauth_transactions (
  id TEXT PRIMARY KEY,
  intent TEXT NOT NULL CHECK (intent IN ('sign_in', 'connect_calendar', 'reconnect')),
  status TEXT NOT NULL CHECK (
    status IN ('pending', 'processing', 'authorized', 'failed', 'consumed')
  ),
  state_hash TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL,
  polling_secret_hash TEXT NOT NULL,
  tasknotes_pkce_challenge TEXT NOT NULL,
  provider_pkce_schema_version INTEGER NOT NULL CHECK (provider_pkce_schema_version = 1),
  provider_pkce_key_version INTEGER NOT NULL CHECK (provider_pkce_key_version > 0),
  provider_pkce_dek_iv TEXT NOT NULL,
  provider_pkce_wrapped_dek TEXT NOT NULL,
  provider_pkce_payload_iv TEXT NOT NULL,
  provider_pkce_ciphertext TEXT NOT NULL,
  authenticated_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  expected_identity_id TEXT,
  authorized_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  authorized_identity_id TEXT,
  authorized_connection_id TEXT,
  processing_owner TEXT,
  processing_expires_at INTEGER,
  device_name TEXT NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'ios', 'android', 'obsidian')),
  failure_code TEXT,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  callback_completed_at INTEGER,
  consumed_at INTEGER,
  FOREIGN KEY (authenticated_principal_id, expected_identity_id)
    REFERENCES external_identities(principal_id, id) ON DELETE CASCADE,
  FOREIGN KEY (authorized_principal_id, authorized_identity_id)
    REFERENCES external_identities(principal_id, id) ON DELETE CASCADE,
  FOREIGN KEY (authorized_principal_id, authorized_connection_id)
    REFERENCES connections(principal_id, id) ON DELETE CASCADE,
  CHECK (
    (intent = 'sign_in'
      AND authenticated_principal_id IS NULL
      AND expected_identity_id IS NULL)
    OR
    (intent IN ('connect_calendar', 'reconnect')
      AND authenticated_principal_id IS NOT NULL
      AND expected_identity_id IS NOT NULL)
  ),
  CHECK (
    (status = 'pending'
      AND processing_owner IS NULL
      AND processing_expires_at IS NULL
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'processing'
      AND processing_owner IS NOT NULL
      AND processing_expires_at IS NOT NULL
      AND length(processing_owner) BETWEEN 1 AND 256
      AND processing_expires_at > created_at
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'authorized'
      AND processing_owner IS NULL
      AND processing_expires_at IS NULL
      AND authorized_principal_id IS NOT NULL
      AND authorized_identity_id IS NOT NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at BETWEEN created_at AND expires_at
      AND consumed_at IS NULL
      AND (
        (intent = 'sign_in' AND authorized_connection_id IS NULL)
        OR
        (intent IN ('connect_calendar', 'reconnect')
          AND authorized_connection_id IS NOT NULL
          AND authorized_principal_id = authenticated_principal_id
          AND authorized_identity_id = expected_identity_id)
      ))
    OR
    (status = 'failed'
      AND processing_owner IS NULL
      AND processing_expires_at IS NULL
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NOT NULL
      AND length(failure_code) BETWEEN 1 AND 128
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at BETWEEN created_at AND expires_at
      AND consumed_at IS NULL)
    OR
    (status = 'consumed'
      AND processing_owner IS NULL
      AND processing_expires_at IS NULL
      AND authorized_principal_id IS NOT NULL
      AND authorized_identity_id IS NOT NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at BETWEEN created_at AND expires_at
      AND consumed_at IS NOT NULL
      AND consumed_at BETWEEN callback_completed_at AND expires_at
      AND (
        (intent = 'sign_in' AND authorized_connection_id IS NULL)
        OR
        (intent IN ('connect_calendar', 'reconnect')
          AND authorized_connection_id IS NOT NULL
          AND authorized_principal_id = authenticated_principal_id
          AND authorized_identity_id = expected_identity_id)
      ))
  )
) STRICT;
CREATE INDEX oauth_transactions_expiry_idx ON oauth_transactions(expires_at);

CREATE TRIGGER oauth_transactions_legal_transition
BEFORE UPDATE OF status ON oauth_transactions
FOR EACH ROW
WHEN NOT (
  (OLD.status = 'pending' AND NEW.status IN ('processing', 'failed'))
  OR (OLD.status = 'processing' AND NEW.status IN ('authorized', 'failed'))
  OR (OLD.status = 'authorized' AND NEW.status = 'consumed')
)
BEGIN
  SELECT RAISE(ABORT, 'illegal oauth transaction transition');
END;

CREATE TRIGGER oauth_transactions_immutable_binding
BEFORE UPDATE OF
  id,
  intent,
  state_hash,
  nonce_hash,
  polling_secret_hash,
  tasknotes_pkce_challenge,
  authenticated_principal_id,
  expected_identity_id,
  created_at,
  expires_at
ON oauth_transactions
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'oauth transaction binding is immutable');
END;
