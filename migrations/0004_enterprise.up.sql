-- 0004_enterprise: P2 Enterprise features schema migration.
-- P2.1 Multi-tenant: tenants table, tenant_id on users/sessions/audit_logs.
-- P2.2 RBAC: permissions, roles, role_permissions, user_roles tables.
-- P2.4 Trusted-device: trusted_devices table for 30d MFA bypass.
-- P2.5 Webhooks: webhook_endpoints, webhook_deliveries tables.
-- P2.6 Audit hash-chaining: prev_hash, record_hash columns on audit_logs.

-- 1. P2.1 Tenants table
CREATE TABLE IF NOT EXISTS `tenants` (
    `id`         VARCHAR(36) NOT NULL,
    `slug`       VARCHAR(64) NOT NULL,
    `name`       VARCHAR(255) NOT NULL,
    `is_active`  BOOLEAN NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NULL,
    `updated_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_tenants_slug` (`slug`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

INSERT IGNORE INTO `tenants` (`id`, `slug`, `name`, `is_active`, `created_at`, `updated_at`)
VALUES ('default', 'default', 'Default Organization', 1, NOW(3), NOW(3));

-- 2. P2.1 Add tenant_id to users, adjust unique keys for multi-tenancy
ALTER TABLE `users`
    ADD COLUMN `tenant_id` VARCHAR(36) NOT NULL DEFAULT 'default' AFTER `id`,
    DROP INDEX `uni_users_email`,
    DROP INDEX `uni_users_username`,
    ADD KEY `idx_users_tenant_id` (`tenant_id`),
    ADD UNIQUE KEY `idx_users_tenant_email` (`tenant_id`, `email`),
    ADD UNIQUE KEY `idx_users_tenant_username` (`tenant_id`, `username`);

-- 3. P2.1 Add tenant_id to sessions
ALTER TABLE `sessions`
    ADD COLUMN `tenant_id` VARCHAR(36) NOT NULL DEFAULT 'default' AFTER `id`,
    ADD KEY `idx_sessions_tenant_id` (`tenant_id`);

-- 4. P2.1 & P2.6 Add tenant_id and hash-chaining columns to audit_logs
ALTER TABLE `audit_logs`
    ADD COLUMN `tenant_id` VARCHAR(36) NOT NULL DEFAULT 'default' AFTER `id`,
    ADD COLUMN `prev_hash` VARCHAR(64) NULL AFTER `detail`,
    ADD COLUMN `record_hash` VARCHAR(64) NULL AFTER `prev_hash`,
    ADD KEY `idx_audit_logs_tenant_id` (`tenant_id`),
    ADD KEY `idx_audit_logs_tenant_created` (`tenant_id`, `created_at`);

-- 5. P2.2 RBAC: permissions, roles, role_permissions, user_roles
CREATE TABLE IF NOT EXISTS `permissions` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`        VARCHAR(100) NOT NULL,
    `description` VARCHAR(255) NULL,
    `created_at`  DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_permissions_name` (`name`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `roles` (
    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id`   VARCHAR(36) NOT NULL DEFAULT 'default',
    `name`        VARCHAR(50) NOT NULL,
    `description` VARCHAR(255) NULL,
    `created_at`  DATETIME(3) NULL,
    `updated_at`  DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_roles_tenant_name` (`tenant_id`, `name`),
    KEY `idx_roles_tenant_id` (`tenant_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `role_permissions` (
    `role_id`       BIGINT UNSIGNED NOT NULL,
    `permission_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`role_id`, `permission_id`),
    CONSTRAINT `fk_role_permissions_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_role_permissions_perm` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `user_roles` (
    `user_id` BIGINT UNSIGNED NOT NULL,
    `role_id` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`user_id`, `role_id`),
    CONSTRAINT `fk_user_roles_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_user_roles_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- Seed baseline standard permissions
INSERT IGNORE INTO `permissions` (`name`, `description`, `created_at`) VALUES
('users:read', 'View user profiles and lists in tenant', NOW(3)),
('users:write', 'Create, update, lock, and unlock users in tenant', NOW(3)),
('sessions:read', 'View active sessions in tenant', NOW(3)),
('sessions:revoke', 'Force-revoke sessions in tenant', NOW(3)),
('audit:read', 'View audit logs in tenant', NOW(3)),
('audit:export', 'Export audit logs in CSV or NDJSON in tenant', NOW(3)),
('roles:write', 'Manage RBAC roles and permission assignments', NOW(3)),
('webhooks:write', 'Manage webhook endpoints in tenant', NOW(3));

-- 6. P2.4 Trusted Devices ("remember me" MFA bypass)
CREATE TABLE IF NOT EXISTS `trusted_devices` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`            BIGINT UNSIGNED NOT NULL,
    `device_hash`        VARCHAR(64) NOT NULL,
    `device_name`        VARCHAR(120),
    `ip_address`         VARCHAR(45),
    `last_used_at`       DATETIME(3) NULL,
    `expires_at`         DATETIME(3) NOT NULL,
    `revoked`            BOOLEAN NOT NULL DEFAULT 0,
    `created_at`         DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_trusted_devices_hash` (`device_hash`),
    KEY `idx_trusted_devices_user` (`user_id`, `revoked`),
    CONSTRAINT `fk_trusted_devices_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- 7. P2.5 Webhooks
CREATE TABLE IF NOT EXISTS `webhook_endpoints` (
    `id`          VARCHAR(36) NOT NULL,
    `tenant_id`   VARCHAR(36) NOT NULL DEFAULT 'default',
    `url`         VARCHAR(500) NOT NULL,
    `secret`      VARCHAR(255) NOT NULL,
    `events`      TEXT NOT NULL,
    `is_active`   BOOLEAN NOT NULL DEFAULT 1,
    `created_at`  DATETIME(3) NULL,
    `updated_at`  DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_webhook_endpoints_tenant` (`tenant_id`, `is_active`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `webhook_deliveries` (
    `id`              VARCHAR(36) NOT NULL,
    `endpoint_id`     VARCHAR(36) NOT NULL,
    `event`           VARCHAR(50) NOT NULL,
    `payload`         TEXT NOT NULL,
    `status`          VARCHAR(20) NOT NULL DEFAULT 'pending',
    `attempts`        INT NOT NULL DEFAULT 0,
    `next_retry_at`   DATETIME(3) NULL,
    `response_status` INT NULL,
    `error_msg`       TEXT NULL,
    `created_at`      DATETIME(3) NULL,
    `updated_at`      DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_webhook_deliveries_pending` (`status`, `next_retry_at`),
    CONSTRAINT `fk_webhook_deliveries_endpoint` FOREIGN KEY (`endpoint_id`) REFERENCES `webhook_endpoints` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
