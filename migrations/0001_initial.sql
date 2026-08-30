PRAGMA foreign_keys = ON;

CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  google_connection_generation INTEGER NOT NULL DEFAULT 0
    CHECK (google_connection_generation >= 0),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at)
) STRICT;

CREATE TABLE external_identities (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  issuer TEXT NOT NULL CHECK (issuer = 'https://accounts.google.com'),
  subject TEXT NOT NULL CHECK (
    length(subject) BETWEEN 1 AND 255
    AND length(CAST(subject AS BLOB)) BETWEEN 1 AND 255
    AND instr(subject, char(0)) = 0
    AND instr(subject, char(1)) = 0
    AND instr(subject, char(2)) = 0
    AND instr(subject, char(3)) = 0
    AND instr(subject, char(4)) = 0
    AND instr(subject, char(5)) = 0
    AND instr(subject, char(6)) = 0
    AND instr(subject, char(7)) = 0
    AND instr(subject, char(8)) = 0
    AND instr(subject, char(9)) = 0
    AND instr(subject, char(10)) = 0
    AND instr(subject, char(11)) = 0
    AND instr(subject, char(12)) = 0
    AND instr(subject, char(13)) = 0
    AND instr(subject, char(14)) = 0
    AND instr(subject, char(15)) = 0
    AND instr(subject, char(16)) = 0
    AND instr(subject, char(17)) = 0
    AND instr(subject, char(18)) = 0
    AND instr(subject, char(19)) = 0
    AND instr(subject, char(20)) = 0
    AND instr(subject, char(21)) = 0
    AND instr(subject, char(22)) = 0
    AND instr(subject, char(23)) = 0
    AND instr(subject, char(24)) = 0
    AND instr(subject, char(25)) = 0
    AND instr(subject, char(26)) = 0
    AND instr(subject, char(27)) = 0
    AND instr(subject, char(28)) = 0
    AND instr(subject, char(29)) = 0
    AND instr(subject, char(30)) = 0
    AND instr(subject, char(31)) = 0
    AND instr(subject, char(127)) = 0
  ),
  email TEXT CHECK (
    email IS NULL OR length(CAST(email AS BLOB)) BETWEEN 1 AND 2048
  ),
  display_name TEXT CHECK (
    display_name IS NULL OR length(CAST(display_name AS BLOB)) BETWEEN 1 AND 2048
  ),
  email_verified INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  UNIQUE (provider, issuer, subject),
  UNIQUE (principal_id),
  UNIQUE (principal_id, id)
) STRICT;

CREATE TRIGGER external_identities_immutable_identity
BEFORE UPDATE ON external_identities
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
  OR NEW.principal_id IS NOT OLD.principal_id
  OR NEW.provider IS NOT OLD.provider
  OR NEW.issuer IS NOT OLD.issuer
  OR NEW.subject IS NOT OLD.subject
  OR NEW.updated_at < OLD.updated_at
BEGIN
  SELECT RAISE(ABORT, 'external identity is immutable');
END;

CREATE TABLE identity_deletion_fences (
  identity_digest TEXT PRIMARY KEY,
  deleted_at INTEGER NOT NULL CHECK (deleted_at >= 0)
) STRICT;

CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider = 'google'),
  status TEXT NOT NULL CHECK (status IN ('active', 'reconnect_required')),
  generation INTEGER NOT NULL CHECK (generation > 0),
  envelope_schema_version INTEGER NOT NULL CHECK (envelope_schema_version = 1),
  key_version INTEGER NOT NULL CHECK (key_version > 0),
  dek_iv TEXT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  payload_iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  token_version INTEGER NOT NULL CHECK (token_version > 0),
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

CREATE TRIGGER connections_validate_insert
BEFORE INSERT ON connections
FOR EACH ROW
WHEN NEW.status IS NOT 'active'
  OR NEW.token_version IS NOT 1
  OR NEW.refresh_lease_owner IS NOT NULL
  OR NEW.refresh_lease_until IS NOT NULL
  OR NEW.refresh_lease_generation IS NOT NULL
  OR NEW.refresh_lease_token_version IS NOT NULL
  OR NOT EXISTS (
    SELECT 1 FROM principals
    WHERE id = NEW.principal_id
      AND NEW.generation = google_connection_generation + 1
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid connection insertion authority');
END;

CREATE TRIGGER connections_advance_epoch_after_insert
AFTER INSERT ON connections
FOR EACH ROW
BEGIN
  UPDATE principals
  SET google_connection_generation = NEW.generation
  WHERE id = NEW.principal_id
    AND google_connection_generation = NEW.generation - 1;
END;

CREATE TRIGGER connections_immutable_ownership
BEFORE UPDATE ON connections
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
  OR NEW.principal_id IS NOT OLD.principal_id
  OR NEW.identity_id IS NOT OLD.identity_id
  OR NEW.provider IS NOT OLD.provider
BEGIN
  SELECT RAISE(ABORT, 'connection ownership is immutable');
END;

CREATE TRIGGER connections_validate_update
BEFORE UPDATE ON connections
FOR EACH ROW
WHEN NEW.created_at IS NOT OLD.created_at
  OR NEW.updated_at < OLD.updated_at
  OR NOT (
    (
      NEW.generation = OLD.generation + 1
      AND NEW.token_version = OLD.token_version + 1
      AND NEW.status = 'active'
      AND OLD.status IN ('active', 'reconnect_required')
      AND NEW.envelope_schema_version = OLD.envelope_schema_version
      AND NEW.key_version >= OLD.key_version
      AND NEW.dek_iv IS NOT OLD.dek_iv
      AND NEW.wrapped_dek IS NOT OLD.wrapped_dek
      AND NEW.payload_iv IS NOT OLD.payload_iv
      AND NEW.ciphertext IS NOT OLD.ciphertext
      AND NEW.refresh_lease_owner IS NULL
      AND NEW.refresh_lease_until IS NULL
      AND NEW.refresh_lease_generation IS NULL
      AND NEW.refresh_lease_token_version IS NULL
      AND EXISTS (
        SELECT 1 FROM principals
        WHERE id = OLD.principal_id
          AND google_connection_generation = OLD.generation
      )
    )
    OR
    (
      NEW.generation = OLD.generation
      AND NEW.token_version = OLD.token_version + 1
      AND OLD.status = 'active'
      AND NEW.status = 'active'
      AND NEW.envelope_schema_version = OLD.envelope_schema_version
      AND NEW.key_version >= OLD.key_version
      AND NEW.dek_iv IS NOT OLD.dek_iv
      AND NEW.wrapped_dek IS NOT OLD.wrapped_dek
      AND NEW.payload_iv IS NOT OLD.payload_iv
      AND NEW.ciphertext IS NOT OLD.ciphertext
      AND NEW.refresh_lease_owner IS NULL
      AND NEW.refresh_lease_until IS NULL
      AND NEW.refresh_lease_generation IS NULL
      AND NEW.refresh_lease_token_version IS NULL
    )
    OR
    (
      NEW.generation = OLD.generation
      AND NEW.token_version = OLD.token_version
      AND NEW.status = OLD.status
      AND NEW.envelope_schema_version = OLD.envelope_schema_version
      AND NEW.key_version > OLD.key_version
      AND NEW.dek_iv IS NOT OLD.dek_iv
      AND NEW.wrapped_dek IS NOT OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.refresh_lease_owner IS OLD.refresh_lease_owner
      AND NEW.refresh_lease_until IS OLD.refresh_lease_until
      AND NEW.refresh_lease_generation IS OLD.refresh_lease_generation
      AND NEW.refresh_lease_token_version IS OLD.refresh_lease_token_version
    )
    OR
    (
      NEW.generation = OLD.generation
      AND NEW.token_version = OLD.token_version
      AND (NEW.status = OLD.status OR (OLD.status = 'active' AND NEW.status = 'reconnect_required'))
      AND NEW.envelope_schema_version = OLD.envelope_schema_version
      AND NEW.key_version = OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid connection authority transition');
END;

CREATE TRIGGER connections_advance_epoch_after_replacement
AFTER UPDATE ON connections
FOR EACH ROW
WHEN NEW.generation = OLD.generation + 1
BEGIN
  UPDATE principals
  SET google_connection_generation = NEW.generation
  WHERE id = NEW.principal_id
    AND google_connection_generation = OLD.generation;
END;

CREATE TRIGGER connections_advance_epoch_before_delete
BEFORE DELETE ON connections
FOR EACH ROW
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM principals
    WHERE id = OLD.principal_id
      AND google_connection_generation IS NOT OLD.generation
  ) THEN RAISE(ABORT, 'invalid connection deletion authority') END;
  UPDATE principals
  SET google_connection_generation = OLD.generation + 1
  WHERE id = OLD.principal_id
    AND google_connection_generation = OLD.generation;
END;

CREATE TABLE oauth_transactions (
  id TEXT PRIMARY KEY,
  intent TEXT NOT NULL CHECK (intent IN ('sign_in', 'connect_calendar')),
  status TEXT NOT NULL CHECK (
    status IN ('pending', 'exchanging', 'authorized', 'failed', 'expired', 'consumed')
  ),
  state_hash TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL,
  polling_secret_hash TEXT NOT NULL,
  tasknotes_pkce_challenge TEXT NOT NULL,
  provider_pkce_schema_version INTEGER CHECK (
    provider_pkce_schema_version IS NULL OR provider_pkce_schema_version = 1
  ),
  provider_pkce_key_version INTEGER CHECK (
    provider_pkce_key_version IS NULL OR provider_pkce_key_version > 0
  ),
  provider_pkce_dek_iv TEXT,
  provider_pkce_wrapped_dek TEXT,
  provider_pkce_payload_iv TEXT,
  provider_pkce_ciphertext TEXT,
  authenticated_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  expected_identity_id TEXT,
  expected_connection_generation INTEGER CHECK (
    expected_connection_generation IS NULL OR expected_connection_generation >= 0
  ),
  expected_connection_id TEXT,
  expected_token_version INTEGER CHECK (
    expected_token_version IS NULL OR expected_token_version > 0
  ),
  target_connection_id TEXT,
  target_connection_generation INTEGER CHECK (
    target_connection_generation IS NULL OR target_connection_generation > 0
  ),
  target_token_version INTEGER CHECK (
    target_token_version IS NULL OR target_token_version > 0
  ),
  authorized_principal_id TEXT REFERENCES principals(id) ON DELETE CASCADE,
  authorized_identity_id TEXT,
  authorized_connection_id TEXT,
  exchange_started_at INTEGER,
  exchange_deadline_at INTEGER,
  device_name TEXT NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'ios', 'android', 'obsidian')),
  failure_code TEXT CHECK (
    failure_code IS NULL OR failure_code IN (
      'access_denied', 'identity_mismatch', 'authorization_failed'
    )
  ),
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
    (exchange_started_at IS NULL AND exchange_deadline_at IS NULL)
    OR
    (exchange_started_at IS NOT NULL
      AND exchange_deadline_at IS NOT NULL
      AND exchange_started_at BETWEEN created_at AND expires_at - 1
      AND exchange_deadline_at BETWEEN exchange_started_at + 1 AND expires_at)
  ),
  CHECK (
    (provider_pkce_schema_version IS NULL
      AND provider_pkce_key_version IS NULL
      AND provider_pkce_dek_iv IS NULL
      AND provider_pkce_wrapped_dek IS NULL
      AND provider_pkce_payload_iv IS NULL
      AND provider_pkce_ciphertext IS NULL)
    OR
    (provider_pkce_schema_version IS NOT NULL
      AND provider_pkce_key_version IS NOT NULL
      AND provider_pkce_dek_iv IS NOT NULL
      AND provider_pkce_wrapped_dek IS NOT NULL
      AND provider_pkce_payload_iv IS NOT NULL
      AND provider_pkce_ciphertext IS NOT NULL)
  ),
  CHECK (
    (intent = 'sign_in'
      AND authenticated_principal_id IS NULL
      AND expected_identity_id IS NULL
      AND expected_connection_generation IS NULL
      AND expected_connection_id IS NULL
      AND expected_token_version IS NULL
      AND target_connection_id IS NULL
      AND target_connection_generation IS NULL
      AND target_token_version IS NULL)
    OR
    (intent = 'connect_calendar'
      AND authenticated_principal_id IS NOT NULL
      AND expected_identity_id IS NOT NULL
      AND expected_connection_generation IS NOT NULL
      AND target_connection_id IS NOT NULL
      AND target_connection_generation = expected_connection_generation + 1
      AND (
        (expected_connection_id IS NULL
          AND expected_token_version IS NULL
          AND target_token_version = 1)
        OR
        (expected_connection_id IS NOT NULL
          AND expected_token_version IS NOT NULL
          AND target_connection_id = expected_connection_id
          AND target_token_version = expected_token_version + 1)
      ))
  ),
  CHECK (
    (status = 'pending'
      AND provider_pkce_schema_version IS NOT NULL
      AND exchange_started_at IS NULL
      AND exchange_deadline_at IS NULL
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'exchanging'
      AND provider_pkce_schema_version IS NULL
      AND exchange_started_at IS NOT NULL
      AND exchange_deadline_at IS NOT NULL
      AND exchange_started_at BETWEEN created_at AND expires_at - 1
      AND exchange_deadline_at BETWEEN exchange_started_at + 1 AND expires_at
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'authorized'
      AND provider_pkce_schema_version IS NULL
      AND exchange_started_at IS NOT NULL
      AND exchange_deadline_at IS NOT NULL
      AND exchange_started_at BETWEEN created_at AND expires_at - 1
      AND exchange_deadline_at BETWEEN exchange_started_at + 1 AND expires_at
      AND authorized_principal_id IS NOT NULL
      AND authorized_identity_id IS NOT NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at >= created_at
      AND callback_completed_at < expires_at
      AND consumed_at IS NULL
      AND (
        (intent = 'sign_in' AND authorized_connection_id IS NULL)
        OR
        (intent = 'connect_calendar'
          AND authorized_connection_id = target_connection_id
          AND authorized_principal_id = authenticated_principal_id
          AND authorized_identity_id = expected_identity_id)
      ))
    OR
    (status = 'failed'
      AND provider_pkce_schema_version IS NULL
      AND ((exchange_started_at IS NULL AND exchange_deadline_at IS NULL)
        OR (exchange_started_at IS NOT NULL
          AND exchange_deadline_at IS NOT NULL
          AND exchange_started_at BETWEEN created_at AND expires_at - 1
          AND exchange_deadline_at BETWEEN exchange_started_at + 1 AND expires_at))
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NOT NULL
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at >= created_at
      AND consumed_at IS NULL)
    OR
    (status = 'expired'
      AND provider_pkce_schema_version IS NULL
      AND ((exchange_started_at IS NULL AND exchange_deadline_at IS NULL)
        OR (exchange_started_at IS NOT NULL
          AND exchange_deadline_at IS NOT NULL
          AND exchange_started_at BETWEEN created_at AND expires_at - 1
          AND exchange_deadline_at BETWEEN exchange_started_at + 1 AND expires_at))
      AND authorized_principal_id IS NULL
      AND authorized_identity_id IS NULL
      AND authorized_connection_id IS NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'consumed'
      AND provider_pkce_schema_version IS NULL
      AND exchange_started_at IS NOT NULL
      AND exchange_deadline_at IS NOT NULL
      AND authorized_principal_id IS NOT NULL
      AND authorized_identity_id IS NOT NULL
      AND failure_code IS NULL
      AND callback_completed_at IS NOT NULL
      AND callback_completed_at >= created_at
      AND callback_completed_at < expires_at
      AND consumed_at IS NOT NULL
      AND consumed_at >= callback_completed_at
      AND consumed_at < expires_at
      AND (
        (intent = 'sign_in' AND authorized_connection_id IS NULL)
        OR
        (intent = 'connect_calendar'
          AND authorized_connection_id = target_connection_id
          AND authorized_principal_id = authenticated_principal_id
          AND authorized_identity_id = expected_identity_id)
      ))
  )
) STRICT;
CREATE INDEX oauth_transactions_expiry_idx ON oauth_transactions(expires_at);
CREATE UNIQUE INDEX oauth_transactions_one_active_connect_per_principal
ON oauth_transactions(authenticated_principal_id)
WHERE intent = 'connect_calendar' AND status IN ('pending', 'exchanging');

CREATE TRIGGER oauth_transactions_validate_connect_snapshot
BEFORE INSERT ON oauth_transactions
FOR EACH ROW
WHEN NEW.intent = 'connect_calendar'
  AND NEW.status = 'pending'
  AND NOT (
    EXISTS (
      SELECT 1 FROM principals
      WHERE id = NEW.authenticated_principal_id
        AND google_connection_generation = NEW.expected_connection_generation
    )
    AND (
      (NEW.expected_connection_id IS NULL AND NOT EXISTS (
        SELECT 1 FROM connections
        WHERE principal_id = NEW.authenticated_principal_id AND provider = 'google'
      ))
      OR
      (NEW.expected_connection_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM connections
        WHERE id = NEW.expected_connection_id
          AND principal_id = NEW.authenticated_principal_id
          AND identity_id = NEW.expected_identity_id
          AND provider = 'google'
          AND generation = NEW.expected_connection_generation
          AND token_version = NEW.expected_token_version
      ))
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid connect transaction snapshot');
END;

CREATE TRIGGER oauth_transactions_legal_transition
BEFORE UPDATE ON oauth_transactions
FOR EACH ROW
WHEN NEW.status IS NOT OLD.status
  AND NOT (
    (OLD.status = 'pending' AND NEW.status IN ('exchanging', 'failed', 'expired'))
    OR (OLD.status = 'exchanging' AND NEW.status IN ('authorized', 'failed', 'expired'))
    OR (OLD.status = 'authorized' AND NEW.status IN ('consumed', 'expired'))
  )
BEGIN
  SELECT RAISE(ABORT, 'illegal oauth transaction transition');
END;

CREATE TRIGGER oauth_transactions_immutable_binding
BEFORE UPDATE ON oauth_transactions
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
  OR NEW.intent IS NOT OLD.intent
  OR NEW.state_hash IS NOT OLD.state_hash
  OR NEW.nonce_hash IS NOT OLD.nonce_hash
  OR NEW.polling_secret_hash IS NOT OLD.polling_secret_hash
  OR NEW.tasknotes_pkce_challenge IS NOT OLD.tasknotes_pkce_challenge
  OR NEW.authenticated_principal_id IS NOT OLD.authenticated_principal_id
  OR NEW.expected_identity_id IS NOT OLD.expected_identity_id
  OR NEW.expected_connection_generation IS NOT OLD.expected_connection_generation
  OR NEW.expected_connection_id IS NOT OLD.expected_connection_id
  OR NEW.expected_token_version IS NOT OLD.expected_token_version
  OR NEW.target_connection_id IS NOT OLD.target_connection_id
  OR NEW.target_connection_generation IS NOT OLD.target_connection_generation
  OR NEW.target_token_version IS NOT OLD.target_token_version
  OR NEW.device_name IS NOT OLD.device_name
  OR NEW.client_kind IS NOT OLD.client_kind
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at
  OR (
    (NEW.exchange_started_at IS NOT OLD.exchange_started_at
      OR NEW.exchange_deadline_at IS NOT OLD.exchange_deadline_at)
    AND NOT (
      OLD.status = 'pending'
      AND NEW.status = 'exchanging'
      AND OLD.exchange_started_at IS NULL
      AND OLD.exchange_deadline_at IS NULL
      AND NEW.exchange_started_at IS NOT NULL
      AND NEW.exchange_deadline_at IS NOT NULL
    )
  )
  OR (
    (NEW.provider_pkce_schema_version IS NOT OLD.provider_pkce_schema_version
      OR NEW.provider_pkce_key_version IS NOT OLD.provider_pkce_key_version
      OR NEW.provider_pkce_dek_iv IS NOT OLD.provider_pkce_dek_iv
      OR NEW.provider_pkce_wrapped_dek IS NOT OLD.provider_pkce_wrapped_dek
      OR NEW.provider_pkce_payload_iv IS NOT OLD.provider_pkce_payload_iv
      OR NEW.provider_pkce_ciphertext IS NOT OLD.provider_pkce_ciphertext)
    AND NOT (
      OLD.status = 'pending'
      AND NEW.status IN ('exchanging', 'failed', 'expired')
      AND OLD.provider_pkce_schema_version IS NOT NULL
      AND OLD.provider_pkce_key_version IS NOT NULL
      AND OLD.provider_pkce_dek_iv IS NOT NULL
      AND OLD.provider_pkce_wrapped_dek IS NOT NULL
      AND OLD.provider_pkce_payload_iv IS NOT NULL
      AND OLD.provider_pkce_ciphertext IS NOT NULL
      AND NEW.provider_pkce_schema_version IS NULL
      AND NEW.provider_pkce_key_version IS NULL
      AND NEW.provider_pkce_dek_iv IS NULL
      AND NEW.provider_pkce_wrapped_dek IS NULL
      AND NEW.provider_pkce_payload_iv IS NULL
      AND NEW.provider_pkce_ciphertext IS NULL
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'oauth transaction binding is immutable');
END;

CREATE TRIGGER oauth_transactions_cleanup_expired_authorized_connect
AFTER UPDATE ON oauth_transactions
FOR EACH ROW
WHEN OLD.intent = 'connect_calendar'
  AND OLD.status = 'authorized'
  AND NEW.status = 'expired'
BEGIN
  DELETE FROM connections
  WHERE id = OLD.authorized_connection_id
    AND principal_id = OLD.authorized_principal_id
    AND identity_id = OLD.authorized_identity_id
    AND generation = OLD.target_connection_generation
    AND EXISTS (
      SELECT 1 FROM principals
      WHERE id = OLD.authorized_principal_id
        AND google_connection_generation = OLD.target_connection_generation
    );
END;

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
  revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  redemption_transaction_id TEXT UNIQUE
    REFERENCES oauth_transactions(id) ON DELETE SET NULL
) STRICT;
CREATE INDEX device_sessions_principal_idx ON device_sessions(principal_id);
CREATE INDEX device_sessions_expiry_idx ON device_sessions(idle_expires_at, absolute_expires_at);

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
