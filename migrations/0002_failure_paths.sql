ALTER TABLE oauth_transactions ADD COLUMN confirmation_code_hash TEXT
  CHECK (confirmation_code_hash IS NULL OR length(confirmation_code_hash) = 43);
ALTER TABLE calendars DROP COLUMN color;
ALTER TABLE calendars DROP COLUMN etag;

DROP TRIGGER connections_validate_update;
CREATE TRIGGER connections_validate_update
BEFORE UPDATE ON connections
FOR EACH ROW
WHEN NEW.created_at IS NOT OLD.created_at
  OR NEW.updated_at < OLD.updated_at
  OR (
    NEW.discovery_version IS NOT OLD.discovery_version
    AND NOT (
      NEW.discovery_version = OLD.discovery_version + 1
      AND OLD.discovery_lease_owner IS NOT NULL
      AND OLD.discovery_lease_generation IS OLD.generation
      AND OLD.discovery_lease_token_version IS OLD.token_version
      AND NEW.discovery_lease_owner IS NULL
      AND NEW.discovery_lease_until IS NULL
      AND NEW.discovery_lease_generation IS NULL
      AND NEW.discovery_lease_token_version IS NULL
      AND NEW.status = 'active' AND OLD.status = 'active'
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.last_provider_success_at IS NOT NULL
      AND NEW.last_provider_success_at = NEW.updated_at
    )
  )
  OR (OLD.last_provider_success_at IS NOT NULL
    AND (NEW.last_provider_success_at IS NULL
      OR NEW.last_provider_success_at < OLD.last_provider_success_at))
  OR NOT (
    (
      NEW.generation = OLD.generation + 1
      AND NEW.token_version = OLD.token_version + 1
      AND OLD.status IN ('active', 'reconnect_required')
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
      AND NEW.discovery_lease_owner IS NULL
      AND NEW.discovery_lease_until IS NULL
      AND NEW.discovery_lease_generation IS NULL
      AND NEW.discovery_lease_token_version IS NULL
      AND EXISTS (
        SELECT 1 FROM principals
        WHERE id = OLD.principal_id
          AND google_connection_generation = OLD.generation
      )
    )
    OR
    (
      NEW.last_provider_success_at IS OLD.last_provider_success_at
      AND OLD.status = 'active'
      AND NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND (OLD.refresh_lease_owner IS NULL OR OLD.refresh_lease_until <= NEW.updated_at)
      AND NEW.refresh_lease_owner IS NOT NULL
      AND NEW.refresh_lease_until > NEW.updated_at
      AND NEW.refresh_lease_until <= NEW.updated_at + 120
      AND NEW.refresh_lease_generation IS NEW.generation
      AND NEW.refresh_lease_token_version IS NEW.token_version
      AND NEW.discovery_lease_owner IS OLD.discovery_lease_owner
      AND NEW.discovery_lease_until IS OLD.discovery_lease_until
      AND NEW.discovery_lease_generation IS OLD.discovery_lease_generation
      AND NEW.discovery_lease_token_version IS OLD.discovery_lease_token_version
    )
    OR
    (
      NEW.last_provider_success_at IS OLD.last_provider_success_at
      AND OLD.refresh_lease_owner IS NOT NULL
      AND OLD.refresh_lease_generation IS OLD.generation
      AND OLD.refresh_lease_token_version IS OLD.token_version
      AND NEW.refresh_lease_owner IS NULL
      AND NEW.refresh_lease_until IS NULL
      AND NEW.refresh_lease_generation IS NULL
      AND NEW.refresh_lease_token_version IS NULL
      AND NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.discovery_lease_owner IS OLD.discovery_lease_owner
      AND NEW.discovery_lease_until IS OLD.discovery_lease_until
      AND NEW.discovery_lease_generation IS OLD.discovery_lease_generation
      AND NEW.discovery_lease_token_version IS OLD.discovery_lease_token_version
    )
    OR
    (
      OLD.status = 'active'
      AND NEW.status = 'active'
      AND OLD.refresh_lease_owner IS NOT NULL
      AND OLD.refresh_lease_generation IS OLD.generation
      AND OLD.refresh_lease_token_version IS OLD.token_version
      AND NEW.generation IS OLD.generation
      AND NEW.token_version = OLD.token_version + 1
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version >= OLD.key_version
      AND NEW.dek_iv IS NOT OLD.dek_iv
      AND NEW.wrapped_dek IS NOT OLD.wrapped_dek
      AND NEW.payload_iv IS NOT OLD.payload_iv
      AND NEW.ciphertext IS NOT OLD.ciphertext
      AND NEW.refresh_lease_owner IS NULL
      AND NEW.refresh_lease_until IS NULL
      AND NEW.refresh_lease_generation IS NULL
      AND NEW.refresh_lease_token_version IS NULL
      AND NEW.discovery_lease_owner IS NULL
      AND NEW.discovery_lease_until IS NULL
      AND NEW.discovery_lease_generation IS NULL
      AND NEW.discovery_lease_token_version IS NULL
    )
    OR
    (
      NEW.last_provider_success_at IS OLD.last_provider_success_at
      AND OLD.status = 'active'
      AND NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND (OLD.discovery_lease_owner IS NULL OR OLD.discovery_lease_until <= NEW.updated_at)
      AND NEW.discovery_lease_owner IS NOT NULL
      AND NEW.discovery_lease_until > NEW.updated_at
      AND NEW.discovery_lease_until <= NEW.updated_at + 60
      AND NEW.discovery_lease_generation IS NEW.generation
      AND NEW.discovery_lease_token_version IS NEW.token_version
      AND NEW.refresh_lease_owner IS OLD.refresh_lease_owner
      AND NEW.refresh_lease_until IS OLD.refresh_lease_until
      AND NEW.refresh_lease_generation IS OLD.refresh_lease_generation
      AND NEW.refresh_lease_token_version IS OLD.refresh_lease_token_version
    )
    OR
    (
      (
        NEW.last_provider_success_at IS OLD.last_provider_success_at
        OR (
          NEW.last_provider_success_at IS NOT NULL
          AND (OLD.last_provider_success_at IS NULL
            OR NEW.last_provider_success_at > OLD.last_provider_success_at)
          AND NEW.last_provider_success_at = NEW.updated_at
          AND NEW.discovery_version = OLD.discovery_version + 1
        )
      )
      AND OLD.discovery_lease_owner IS NOT NULL
      AND OLD.discovery_lease_generation IS OLD.generation
      AND OLD.discovery_lease_token_version IS OLD.token_version
      AND NEW.discovery_lease_owner IS NULL
      AND NEW.discovery_lease_until IS NULL
      AND NEW.discovery_lease_generation IS NULL
      AND NEW.discovery_lease_token_version IS NULL
      AND NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.refresh_lease_owner IS OLD.refresh_lease_owner
      AND NEW.refresh_lease_until IS OLD.refresh_lease_until
      AND NEW.refresh_lease_generation IS OLD.refresh_lease_generation
      AND NEW.refresh_lease_token_version IS OLD.refresh_lease_token_version
    )
    OR
    (
      NEW.last_provider_success_at IS OLD.last_provider_success_at
      AND OLD.status = 'active'
      AND NEW.status = 'reconnect_required'
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.refresh_lease_owner IS NULL
      AND NEW.refresh_lease_until IS NULL
      AND NEW.refresh_lease_generation IS NULL
      AND NEW.refresh_lease_token_version IS NULL
      AND NEW.discovery_lease_owner IS NULL
      AND NEW.discovery_lease_until IS NULL
      AND NEW.discovery_lease_generation IS NULL
      AND NEW.discovery_lease_token_version IS NULL
    )
    OR
    (
      NEW.last_provider_success_at IS OLD.last_provider_success_at
      AND NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version > OLD.key_version
      AND NEW.dek_iv IS NOT OLD.dek_iv
      AND NEW.wrapped_dek IS NOT OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.refresh_lease_owner IS OLD.refresh_lease_owner
      AND NEW.refresh_lease_until IS OLD.refresh_lease_until
      AND NEW.refresh_lease_generation IS OLD.refresh_lease_generation
      AND NEW.refresh_lease_token_version IS OLD.refresh_lease_token_version
      AND NEW.discovery_lease_owner IS OLD.discovery_lease_owner
      AND NEW.discovery_lease_until IS OLD.discovery_lease_until
      AND NEW.discovery_lease_generation IS OLD.discovery_lease_generation
      AND NEW.discovery_lease_token_version IS OLD.discovery_lease_token_version
    )
    OR
    (
      NEW.status IS OLD.status
      AND NEW.generation IS OLD.generation
      AND NEW.token_version IS OLD.token_version
      AND NEW.envelope_schema_version IS OLD.envelope_schema_version
      AND NEW.key_version IS OLD.key_version
      AND NEW.dek_iv IS OLD.dek_iv
      AND NEW.wrapped_dek IS OLD.wrapped_dek
      AND NEW.payload_iv IS OLD.payload_iv
      AND NEW.ciphertext IS OLD.ciphertext
      AND NEW.refresh_lease_owner IS OLD.refresh_lease_owner
      AND NEW.refresh_lease_until IS OLD.refresh_lease_until
      AND NEW.refresh_lease_generation IS OLD.refresh_lease_generation
      AND NEW.refresh_lease_token_version IS OLD.refresh_lease_token_version
      AND NEW.discovery_lease_owner IS OLD.discovery_lease_owner
      AND NEW.discovery_lease_until IS OLD.discovery_lease_until
      AND NEW.discovery_lease_generation IS OLD.discovery_lease_generation
      AND NEW.discovery_lease_token_version IS OLD.discovery_lease_token_version
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid connection authority transition');
END;

DROP TRIGGER oauth_transactions_legal_transition;
CREATE TRIGGER oauth_transactions_legal_transition
BEFORE UPDATE ON oauth_transactions
FOR EACH ROW
WHEN NEW.status IS NOT OLD.status
  AND NOT (
    (OLD.status = 'pending' AND NEW.status IN ('exchanging', 'failed', 'expired'))
    OR (OLD.status = 'exchanging' AND NEW.status IN ('authorized', 'failed', 'expired'))
    OR (OLD.status = 'authorized' AND NEW.status IN ('consumed', 'expired'))
    OR (OLD.status = 'authorized' AND OLD.intent = 'sign_in' AND NEW.status = 'failed')
  )
BEGIN
  SELECT RAISE(ABORT, 'illegal oauth transaction transition');
END;

CREATE TRIGGER oauth_transactions_confirmation_immutable
BEFORE UPDATE OF confirmation_code_hash ON oauth_transactions
FOR EACH ROW
WHEN NEW.confirmation_code_hash IS NOT OLD.confirmation_code_hash
  AND NOT (OLD.intent = 'sign_in' AND OLD.status = 'exchanging'
    AND NEW.status = 'authorized' AND OLD.confirmation_code_hash IS NULL
    AND NEW.confirmation_code_hash IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'oauth confirmation binding is immutable');
END;

CREATE TRIGGER device_sessions_advance_principal_activity
AFTER UPDATE OF last_used_at ON device_sessions
FOR EACH ROW
WHEN NEW.last_used_at > OLD.last_used_at
BEGIN
  UPDATE principals SET last_active_at = MAX(last_active_at, NEW.last_used_at)
  WHERE id = NEW.principal_id;
END;
