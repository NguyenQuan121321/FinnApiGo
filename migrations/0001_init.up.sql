-- 0001_init: baseline schema matching the GORM models exactly (R1).
-- Derived from internal/models: users, refresh_tokens, audit_logs,
-- used_tokens, totp_devices, recovery_codes, oauth_identities.
-- DATETIME precision 3 mirrors GORM's MySQL mapping; loc=UTC DSN governs
-- interpretation. Idempotent ONLY via the migrate version bookkeeping —
-- do not run by hand against a database migrate has not stamped.

CREATE TABLE IF NOT EXISTS `users` (
    `id`                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username`             VARCHAR(50) NOT NULL,
    `email`                VARCHAR(255) NOT NULL,
    `password`             VARCHAR(255) NOT NULL,
    `full_name`            VARCHAR(255),
    `role`                 VARCHAR(20) NOT NULL DEFAULT 'user',
    `is_active`            BOOLEAN NOT NULL DEFAULT 1,
    `is_email_verified`    BOOLEAN NOT NULL DEFAULT 0,
    `failed_login_attempts` BIGINT NOT NULL DEFAULT 0,
    `locked_until`         DATETIME(3) NULL,
    `pwd_version`          BIGINT NOT NULL DEFAULT 0,
    `created_at`           DATETIME(3) NULL,
    `updated_at`           DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_users_username` (`username`),
    UNIQUE KEY `uni_users_email` (`email`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `refresh_tokens` (
    `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`          BIGINT UNSIGNED NOT NULL,
    `token_hash`       VARCHAR(64) NOT NULL,
    `expires_at`       DATETIME(3) NOT NULL,
    `revoked`          BOOLEAN NOT NULL DEFAULT 0,
    `ip_address`       VARCHAR(45),
    `user_agent`       VARCHAR(500),
    `device_name`      VARCHAR(120),
    `location_estimate` VARCHAR(120) DEFAULT 'Unknown',
    `last_active_at`   DATETIME(3) NULL,
    `created_at`       DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_refresh_tokens_token_hash` (`token_hash`),
    KEY `idx_refresh_tokens_user_id` (`user_id`),
    KEY `idx_refresh_tokens_expires_at` (`expires_at`),
    KEY `idx_refresh_tokens_revoked` (`revoked`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    BIGINT UNSIGNED NULL,
    `email`      VARCHAR(255),
    `event`      VARCHAR(40) NOT NULL,
    `ip_address` VARCHAR(45),
    `success`    BOOLEAN NOT NULL DEFAULT 0,
    `detail`     VARCHAR(500),
    `created_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_audit_logs_user_id` (`user_id`),
    KEY `idx_audit_logs_event` (`event`),
    KEY `idx_audit_logs_created_at` (`created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `used_tokens` (
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `jti`        VARCHAR(64) NOT NULL,
    `token_type` VARCHAR(20) NOT NULL,
    `user_id`    BIGINT UNSIGNED NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_used_tokens_jti` (`jti`),
    KEY `idx_used_tokens_user_id` (`user_id`),
    KEY `idx_used_tokens_expires_at` (`expires_at`),
    KEY `idx_used_tokens_created_at` (`created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `totp_devices` (
    `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`                 BIGINT UNSIGNED NOT NULL,
    `secret`                  VARCHAR(255) NOT NULL,
    `secret_encrypted`        VARCHAR(512),
    `pending_secret_encrypted` VARCHAR(512),
    `enabled`                 BOOLEAN NOT NULL DEFAULT 0,
    `created_at`              DATETIME(3) NULL,
    `updated_at`              DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_totp_devices_user_id` (`user_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `recovery_codes` (
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`        BIGINT UNSIGNED NOT NULL,
    `code_hash`      VARCHAR(255) NOT NULL,
    `code_encrypted` VARCHAR(512),
    `used_at`        DATETIME(3) NULL,
    `created_at`     DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_recovery_codes_user_id` (`user_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE IF NOT EXISTS `oauth_identities` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`           BIGINT UNSIGNED NOT NULL,
    `provider`          VARCHAR(20) NOT NULL,
    `provider_user_id`  VARCHAR(255) NOT NULL,
    `created_at`        DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_oauth_prov_uid` (`provider`, `provider_user_id`),
    KEY `idx_oauth_identities_user_id` (`user_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
