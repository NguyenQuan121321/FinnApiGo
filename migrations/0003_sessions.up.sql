-- 0003_sessions — P0.3: server-side session entity + token-family isolation.
-- One row per successful authentication; every refresh token and access
-- token (sid claim) belongs to exactly one session so a compromised family
-- can be revoked without touching the user's other devices.
-- DATETIME precision 3 mirrors the baseline schema (0001_init).

CREATE TABLE IF NOT EXISTS `sessions` (
    `id`                VARCHAR(36) NOT NULL,
    `user_id`           BIGINT UNSIGNED NOT NULL,
    `ip_address`        VARCHAR(45),
    `user_agent`        VARCHAR(500),
    `device_name`       VARCHAR(120),
    `location_estimate` VARCHAR(120) DEFAULT 'Unknown',
    `revoked`           BOOLEAN NOT NULL DEFAULT 0,
    `last_active_at`    DATETIME(3) NULL,
    `expires_at`        DATETIME(3) NULL,
    `created_at`        DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    KEY `idx_sessions_user_revoked` (`user_id`, `revoked`),
    KEY `idx_sessions_expires_at` (`expires_at`),
    CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

-- Link every refresh token to its session family. Nullable: rows created
-- before this migration keep empty session_id and fall back to the legacy
-- global-revocation behavior on reuse.
ALTER TABLE `refresh_tokens`
    ADD COLUMN `session_id` VARCHAR(36) NULL,
    ADD KEY `idx_refresh_tokens_session_id` (`session_id`);
