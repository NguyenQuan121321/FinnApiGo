-- DESTRUCTIVE: stop admission/workers and independently archive/checkpoint all
-- evidence before rollback. Do not run DOWN to recover application availability.
DROP TABLE IF EXISTS audit_boundaries;
DROP TABLE IF EXISTS audit_outboxes;
DROP TABLE IF EXISTS audit_heads;
ALTER TABLE audit_logs
 DROP INDEX ux_audit_sequence,
 DROP INDEX idx_audit_logs_event_id,
 DROP COLUMN action, DROP COLUMN request_id, DROP COLUMN actor_id,
 DROP COLUMN actor_kind, DROP COLUMN key_id, DROP COLUMN sequence,
 DROP COLUMN event_id, DROP COLUMN version;
