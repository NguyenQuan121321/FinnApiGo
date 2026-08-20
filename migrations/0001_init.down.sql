-- 0001_init (down): drops the baseline schema in dependency-safe order.
DROP TABLE IF EXISTS `oauth_identities`;
DROP TABLE IF EXISTS `recovery_codes`;
DROP TABLE IF EXISTS `totp_devices`;
DROP TABLE IF EXISTS `used_tokens`;
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `refresh_tokens`;
DROP TABLE IF EXISTS `users`;
