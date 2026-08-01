package services

import (
	"sync"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
)

// ---- In-memory mock repositories for unit tests ----
// These satisfy the service-layer interfaces without a DB, so the business
// logic can be tested in pure Go. The real GORM repos are exercised by an
// integration test against a live MySQL (see cmd/server).

type mockUserRepo struct {
	mu          sync.Mutex
	users       map[uint]*models.User
	byEmail     map[string]uint
	byUsername  map[string]uint
	nextID      uint
	failOnFind  error // inject an error if set
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users: map[uint]*models.User{}, byEmail: map[string]uint{}, byUsername: map[string]uint{},
	}
}

func (m *mockUserRepo) Create(user *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	user.ID = m.nextID
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	clone := *user
	m.users[user.ID] = &clone
	m.byEmail[user.Email] = user.ID
	m.byUsername[user.Username] = user.ID
	return nil
}

func (m *mockUserRepo) FindByID(id uint) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, nil
}

func (m *mockUserRepo) FindByEmail(email string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byEmail[email]; ok {
		if u, ok := m.users[id]; ok {
			c := *u
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockUserRepo) FindByUsername(username string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byUsername[username]; ok {
		if u, ok := m.users[id]; ok {
			c := *u
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockUserRepo) Update(user *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[user.ID]; !ok {
		return errNotFound
	}
	clone := *user
	m.users[user.ID] = &clone
	return nil
}

func (m *mockUserRepo) UpdatePassword(user *models.User, hashedPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.Password = hashedPassword
		user.Password = hashedPassword
	}
	return nil
}

func (m *mockUserRepo) IncrementFailedAttempts(user *models.User, lockUntil *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.FailedLoginAttempts++
		user.FailedLoginAttempts = u.FailedLoginAttempts
		if lockUntil != nil {
			u.LockedUntil = lockUntil
			user.LockedUntil = lockUntil
		}
	}
	return nil
}

func (m *mockUserRepo) ResetFailedAttempts(user *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.FailedLoginAttempts = 0
		u.LockedUntil = nil
		user.FailedLoginAttempts = 0
		user.LockedUntil = nil
	}
	return nil
}

func (m *mockUserRepo) SetEmailVerified(user *models.User, verified bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.IsEmailVerified = verified
		user.IsEmailVerified = verified
	}
	return nil
}

// ---- mock refresh token repo ----

type mockTokenRepo struct {
	mu     sync.Mutex
	rows   map[uint]*models.RefreshToken // keyed by row ID
	byHash map[string]uint               // hash -> row ID
	nextID uint
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{rows: map[uint]*models.RefreshToken{}, byHash: map[string]uint{}}
}

func (m *mockTokenRepo) Create(rt *models.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	rt.ID = m.nextID
	rt.CreatedAt = time.Now()
	clone := *rt
	m.rows[rt.ID] = &clone
	m.byHash[rt.TokenHash] = rt.ID
	return nil
}

func (m *mockTokenRepo) FindByHash(hash string) (*models.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byHash[hash]; ok {
		if rt, ok := m.rows[id]; ok {
			c := *rt
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockTokenRepo) Revoke(rt *models.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if row, ok := m.rows[rt.ID]; ok {
		row.Revoked = true
		rt.Revoked = true
	}
	return nil
}

func (m *mockTokenRepo) RevokeAllForUser(userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rt := range m.rows {
		if rt.UserID == userID {
			rt.Revoked = true
		}
	}
	return nil
}

func (m *mockTokenRepo) PurgeExpired(before time.Time) (int64, error) { return 0, nil }

// ---- mock OTP repo ----

type mockOtpRepo struct {
	mu     sync.Mutex
	rows   []*models.OtpCode
	nextID uint
}

func newMockOtpRepo() *mockOtpRepo { return &mockOtpRepo{} }

func (m *mockOtpRepo) Create(o *models.OtpCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	o.ID = m.nextID
	o.CreatedAt = time.Now()
	m.rows = append(m.rows, o)
	return nil
}

func (m *mockOtpRepo) FindLatestActive(userID uint, purpose string) (*models.OtpCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *models.OtpCode
	for _, o := range m.rows {
		if o.UserID == userID && o.Purpose == purpose && !o.IsUsed && time.Now().Before(o.ExpiresAt) {
			if latest == nil || o.CreatedAt.After(latest.CreatedAt) {
				c := *o
				latest = &c
			}
		}
	}
	return latest, nil
}

func (m *mockOtpRepo) Update(o *models.OtpCode) error { return nil }

func (m *mockOtpRepo) MarkUsed(o *models.OtpCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.rows {
		if row.ID == o.ID {
			row.IsUsed = true
			o.IsUsed = true
		}
	}
	return nil
}

func (m *mockOtpRepo) IncrementAttempts(o *models.OtpCode) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.rows {
		if row.ID == o.ID {
			row.AttemptCount++
			o.AttemptCount = row.AttemptCount
			return row.AttemptCount, nil
		}
	}
	return 0, nil
}

func (m *mockOtpRepo) PurgeExpired(before time.Time) (int64, error) { return 0, nil }

// ---- mock audit repo (no-op) ----

type mockAuditRepo struct{}

func (mockAuditRepo) Record(entry *models.AuditLog) {}

// ---- mock notifier (captures last sent values) ----

type mockNotifier struct {
	lastOTPCode   string
	lastOTPPurpose string
	lastReset     string
}

func (n *mockNotifier) SendOTP(to, code, purpose string) error {
	n.lastOTPCode = code
	n.lastOTPPurpose = purpose
	return nil
}

func (n *mockNotifier) SendPasswordReset(to, resetToken string) error {
	n.lastReset = resetToken
	return nil
}

var errNotFound = errNotFoundErr{}

type errNotFoundErr struct{}

func (errNotFoundErr) Error() string { return "not found" }
