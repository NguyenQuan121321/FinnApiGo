-- 0003_sessions down migration: drop the family-isolation link, then the
-- sessions table itself.
ALTER TABLE `refresh_tokens`
    DROP KEY `idx_refresh_tokens_session_id`,
    DROP COLUMN `session_id`;

DROP TABLE IF EXISTS `sessions`;
