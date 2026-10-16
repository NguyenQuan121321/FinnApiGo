-- Disposable rehearsal only. Dropping authoritative state is unsafe while any
-- issued credentials remain usable; production rollback retains these additions.
DROP INDEX idx_sessions_identity ON sessions;
DROP TABLE access_revocations;
ALTER TABLE users DROP COLUMN admin_suspended, DROP COLUMN auth_epoch;
