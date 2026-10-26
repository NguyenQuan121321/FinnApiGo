-- Additive only. Existing context/signatures are not trustworthy: version=0,
-- event_id/sequence=NULL explicitly preserve legacy/unverifiable history.
ALTER TABLE audit_logs
  ADD COLUMN version BIGINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN event_id VARCHAR(36) NULL,
  ADD COLUMN sequence BIGINT UNSIGNED NULL,
  ADD COLUMN key_id VARCHAR(64) NULL,
  ADD COLUMN actor_kind VARCHAR(20) NULL,
  ADD COLUMN actor_id BIGINT UNSIGNED NULL,
  ADD COLUMN request_id VARCHAR(36) NULL,
  ADD COLUMN action VARCHAR(40) NULL,
  ADD UNIQUE KEY idx_audit_logs_event_id (event_id),
  ADD UNIQUE KEY ux_audit_sequence (tenant_id, sequence);

CREATE TABLE audit_heads (
  tenant_id VARCHAR(36) NOT NULL PRIMARY KEY,
  sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  hash VARCHAR(64) NOT NULL,
  pending BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE audit_outboxes (
  event_id VARCHAR(36) NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(36) NOT NULL,
  sequence BIGINT UNSIGNED NOT NULL,
  hash VARCHAR(64) NOT NULL,
  key_id VARCHAR(64) NOT NULL,
  payload LONGTEXT NOT NULL,
  state VARCHAR(16) NOT NULL,
  attempts BIGINT NOT NULL DEFAULT 0,
  available_at DATETIME(3) NULL,
  lease_until DATETIME(3) NULL,
  lease_token VARCHAR(36) NULL,
  last_error VARCHAR(32) NULL,
  created_at DATETIME(3) NULL,
  UNIQUE KEY ux_outbox_sequence (tenant_id, sequence),
  KEY idx_outbox_due (state, available_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE audit_boundaries (
  tenant_id VARCHAR(36) NOT NULL PRIMARY KEY,
  sequence BIGINT UNSIGNED NOT NULL,
  hash VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
