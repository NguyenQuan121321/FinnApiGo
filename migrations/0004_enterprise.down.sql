-- 0004_enterprise.down.sql: Revert Phase 2 Enterprise features schema migration.

DROP TABLE IF EXISTS `webhook_deliveries`;
DROP TABLE IF EXISTS `webhook_endpoints`;
DROP TABLE IF EXISTS `trusted_devices`;
DROP TABLE IF EXISTS `user_roles`;
DROP TABLE IF EXISTS `role_permissions`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `permissions`;

ALTER TABLE `audit_logs`
    DROP KEY `idx_audit_logs_tenant_created`,
    DROP KEY `idx_audit_logs_tenant_id`,
    DROP COLUMN `record_hash`,
    DROP COLUMN `prev_hash`,
    DROP COLUMN `tenant_id`;

ALTER TABLE `sessions`
    DROP KEY `idx_sessions_tenant_id`,
    DROP COLUMN `tenant_id`;

ALTER TABLE `users`
    DROP KEY `idx_users_tenant_username`,
    DROP KEY `idx_users_tenant_email`,
    DROP KEY `idx_users_tenant_id`,
    ADD UNIQUE KEY `uni_users_email` (`email`),
    ADD UNIQUE KEY `uni_users_username` (`username`),
    DROP COLUMN `tenant_id`;

DROP TABLE IF EXISTS `tenants`;
