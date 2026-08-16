package repositories

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// isMySQLDuplicate reports whether err is a MySQL duplicate-key error (1062).
// This is the canonical check used across the repository layer for TOCTOU-
// race fallback handling (§1.7, §1.8).
func isMySQLDuplicate(err error) bool {
	var myErr *mysql.MySQLError
	return errors.As(err, &myErr) && myErr.Number == 1062
}

// ErrTokenAlreadyRevoked is returned by RefreshTokenRepository.Revoke when its
// compare-and-set (WHERE revoked = false) matched no row because the token was
// already revoked (or purged) by a concurrent request. Callers treat it as the
// reuse signal, not as a persistence failure.
var ErrTokenAlreadyRevoked = errors.New("refresh token already revoked")

// isGormDuplicate reports whether err wraps gorm.ErrDuplicatedKey.
// GORM wraps the driver error; checking both paths ensures we catch it
// regardless of GORM version internals.
func isGormDuplicate(err error) bool {
	return errors.Is(err, gorm.ErrDuplicatedKey) || isMySQLDuplicate(err)
}
