ALTER TABLE users
  ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN admin_suspended BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE access_revocations (
  tenant_id VARCHAR(36) NOT NULL,
  jti VARCHAR(64) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  PRIMARY KEY (tenant_id, jti),
  INDEX idx_access_revocations_expires_at (expires_at)
);
CREATE INDEX idx_sessions_identity ON sessions (tenant_id, user_id, id);
