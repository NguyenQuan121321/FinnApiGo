-- W1 — passkey credentials for WebAuthn (Phase 9). One row per registered
-- authenticator. `revoked` extends the catalog's column list: clone detection
-- (W5) and device management (W6) need a durable revoked state rather than a
-- hard delete so re-presenting a cloned credential stays detectable and
-- auditable (same pattern as refresh_tokens.revoked).
CREATE TABLE IF NOT EXISTS `passkey_credentials` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `credential_id` VARBINARY(512) NOT NULL,
    `public_key` BLOB NOT NULL,
    `sign_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `display_name` VARCHAR(255) NOT NULL DEFAULT '',
    `transports` JSON NULL,
    `attestation_type` VARCHAR(64) NOT NULL DEFAULT '',
    `last_used_at` DATETIME NULL,
    `revoked` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uni_passkey_credentials_credential_id` (`credential_id`),
    KEY `idx_passkey_credentials_user_id` (`user_id`),
    CONSTRAINT `fk_passkey_credentials_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
