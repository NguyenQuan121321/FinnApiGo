package services

import (
	"context"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
)

// ---- In-memory mock repositories for unit tests ----
// These satisfy the service-layer interfaces without a DB, so the business
// logic can be tested in pure Go. Every method now takes a context.Context
// (§1.4); the mocks ignore it.

type mockUserRepo struct {
	mu         sync.Mutex
	users      map[uint]*models.User
	byEmail    map[string]uint
	byUsername map[string]uint
	nextID     uint
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users: map[uint]*models.User{}, byEmail: map[string]uint{}, byUsername: map[string]uint{},
	}
}

func (m *mockUserRepo) Create(ctx context.Context, user *models.User) error {
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

func (m *mockUserRepo) FindByID(ctx context.Context, id uint) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, nil
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
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

func (m *mockUserRepo) FindByUsername(ctx context.Context, username string) (*models.User, error) {
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

func (m *mockUserRepo) Update(ctx context.Context, user *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[user.ID]; !ok {
		return errNotFound
	}
	clone := *user
	m.users[user.ID] = &clone
	return nil
}

func (m *mockUserRepo) UpdatePassword(ctx context.Context, user *models.User, hashedPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.Password = hashedPassword
		user.Password = hashedPassword
	}
	return nil
}

func (m *mockUserRepo) IncrementFailedAttempts(ctx context.Context, user *models.User, lockUntil *time.Time) error {
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

func (m *mockUserRepo) ResetFailedAttempts(ctx context.Context, user *models.User) error {
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

func (m *mockUserRepo) SetEmailVerified(ctx context.Context, user *models.User, verified bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[user.ID]; ok {
		u.IsEmailVerified = verified
		user.IsEmailVerified = verified
	}
	return nil
}

func (m *mockUserRepo) BumpPwdVersion(ctx context.Context, userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[userID]; ok {
		u.PwdVersion++
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

func (m *mockTokenRepo) Create(ctx context.Context, rt *models.RefreshToken) error {
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

func (m *mockTokenRepo) FindByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
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

// Revoke mirrors the GORM repository's compare-and-set: revoking an
// already-revoked (or unknown) row reports repositories.ErrTokenAlreadyRevoked
// so the service's reuse-detection path is exercised identically to production.
func (m *mockTokenRepo) Revoke(ctx context.Context, rt *models.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[rt.ID]
	if !ok || row.Revoked {
		return repositories.ErrTokenAlreadyRevoked
	}
	row.Revoked = true
	rt.Revoked = true
	return nil
}

func (m *mockTokenRepo) RevokeAllForUser(ctx context.Context, userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rt := range m.rows {
		if rt.UserID == userID {
			rt.Revoked = true
		}
	}
	return nil
}

// FindActiveByUser returns the caller's non-expired, non-revoked sessions,
// newest activity first — mirrors the GORM repository ordering for parity.
func (m *mockTokenRepo) FindActiveByUser(ctx context.Context, userID uint) ([]models.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []models.RefreshToken
	for _, rt := range m.rows {
		if rt.UserID == userID && !rt.Revoked && rt.ExpiresAt.After(now) {
			out = append(out, *rt)
		}
	}
	// Sort by LastActiveAt desc, then ID desc (stable enough for assertions).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.LastActiveAt.Before(b.LastActiveAt) ||
				(a.LastActiveAt.Equal(b.LastActiveAt) && a.ID < b.ID) {
				out[j-1], out[j] = out[j], out[j-1]
			} else {
				break
			}
		}
	}
	return out, nil
}

// RevokeByID mimics the GORM repo: scope to userID, return gorm.ErrRecordNotFound
// when no row matched (the service maps that sentinel to ErrSessionNotFound).
func (m *mockTokenRepo) RevokeByID(ctx context.Context, id, userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rt := range m.rows {
		if rt.ID == id && rt.UserID == userID {
			rt.Revoked = true
			return nil
		}
	}
	return gorm.ErrRecordNotFound
}

// TouchLastActive was removed with the dead session-bump feature — rotation
// stamps the fresh row, which is the authoritative activity marker.

func (m *mockTokenRepo) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

// ---- mock used-token repo (§1.8) ----

type mockUsedTokenRepo struct {
	mu     sync.Mutex
	used   map[string]bool
	markOK bool // what MarkUsed should return (true = first use wins)
}

func newMockUsedTokenRepo() *mockUsedTokenRepo {
	return &mockUsedTokenRepo{used: map[string]bool{}, markOK: true}
}

func (m *mockUsedTokenRepo) MarkUsed(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used[jti] {
		return false, nil
	}
	m.used[jti] = true
	return true, nil
}

func (m *mockUsedTokenRepo) IsUsed(ctx context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.used[jti], nil
}

// ---- mock audit repo (records events for assertions) ----

type mockAuditRepo struct {
	mu      sync.Mutex
	entries []*models.AuditLog
}

func (m *mockAuditRepo) Record(ctx context.Context, entry *models.AuditLog) {
	m.mu.Lock()
	m.entries = append(m.entries, entry)
	m.mu.Unlock()
}

func (m *mockAuditRepo) byEvent(event string) []*models.AuditLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.AuditLog
	for _, e := range m.entries {
		if e.Event == event {
			out = append(out, e)
		}
	}
	return out
}

func (m *mockAuditRepo) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// ---- mock notifier (captures last sent values) ----

type mockNotifier struct {
	mu            sync.Mutex
	lastReset     string
	lastVerify    string
	lastAlertIP   string
	lastAlertDev  string
	alertsSent    int
	verifySendErr error
}

func (n *mockNotifier) SendPasswordReset(ctx context.Context, to, resetToken string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lastReset = resetToken
	return nil
}

func (n *mockNotifier) SendEmailVerification(ctx context.Context, to, verifyToken string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.verifySendErr != nil {
		return n.verifySendErr
	}
	n.lastVerify = verifyToken
	return nil
}

func (n *mockNotifier) SendNewLoginAlert(ctx context.Context, to, ip, deviceName string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.alertsSent++
	n.lastAlertIP = ip
	n.lastAlertDev = deviceName
	return nil
}

// alertCount is the thread-safe reader for assertions — the alert is delivered
// from a fire-and-forget goroutine, so tests must not read the fields directly.
func (n *mockNotifier) alertCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.alertsSent
}

func (n *mockNotifier) lastAlert() (ip, device string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastAlertIP, n.lastAlertDev
}

// ---- mock store (for §1.8 jti tracking in tests) ----

type mockStore struct {
	mu         sync.Mutex
	data       map[string]any
	setNXCalls int
}

func newMockStore() *mockStore {
	return &mockStore{data: map[string]any{}}
}

func (m *mockStore) SetNX(key string, value any, ttl time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setNXCalls++
	if _, ok := m.data[key]; ok {
		return false
	}
	m.data[key] = value
	return true
}

func (m *mockStore) IncrBy(key string, delta int64, ttl time.Duration) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _ := m.data[key].(int64)
	cur += delta
	m.data[key] = cur
	return cur
}

func (m *mockStore) Get(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	return v, ok
}

// Take atomically returns and deletes — mirrors the production contract.
func (m *mockStore) Take(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, false
	}
	delete(m.data, key)
	return v, true
}

func (m *mockStore) Set(key string, value any, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

func (m *mockStore) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// ---- mock captcha verifier (§3 adaptive CAPTCHA tests) ----

// mockCaptchaVerifier lets tests control whether CAPTCHA verification passes.
// err != nil => Verify returns that error (simulating a rejected/missing token).
type mockCaptchaVerifier struct {
	err   error
	calls int
	token string
}

func (m *mockCaptchaVerifier) Verify(ctx context.Context, token string) error {
	m.calls++
	m.token = token
	return m.err
}

// ---- mock TOTP repo ----

type mockTOTPRepo struct {
	mu         sync.Mutex
	devices    map[uint]*models.TOTPDevice
	codes      map[uint][]models.RecoveryCode
	nextID     uint
	upsertErr  error
	replaceErr error
}

func newMockTOTPRepo() *mockTOTPRepo {
	return &mockTOTPRepo{
		devices: map[uint]*models.TOTPDevice{},
		codes:   map[uint][]models.RecoveryCode{},
	}
}

func (m *mockTOTPRepo) Upsert(ctx context.Context, d *models.TOTPDevice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertErr != nil {
		return m.upsertErr
	}
	if d.ID == 0 {
		m.nextID++
		d.ID = m.nextID
	}
	clone := *d
	m.devices[d.UserID] = &clone
	return nil
}

func (m *mockTOTPRepo) FindByUserID(ctx context.Context, userID uint) (*models.TOTPDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[userID]
	if !ok {
		return nil, nil
	}
	c := *d
	return &c, nil
}

func (m *mockTOTPRepo) ReplaceRecoveryCodes(ctx context.Context, userID uint, codes []*models.RecoveryCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.replaceErr != nil {
		return m.replaceErr
	}
	delete(m.codes, userID)
	for _, c := range codes {
		c.ID = m.nextID
		m.nextID++
		m.codes[c.UserID] = append(m.codes[c.UserID], *c)
	}
	return nil
}

func (m *mockTOTPRepo) ActiveRecoveryCodes(ctx context.Context, userID uint) ([]models.RecoveryCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []models.RecoveryCode
	for _, c := range m.codes[userID] {
		if c.UsedAt == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// MarkRecoveryCodeUsed mirrors the GORM repository's compare-and-set on
// used_at IS NULL: the second of two concurrent marks reports
// repositories.ErrRecoveryCodeUsed.
func (m *mockTOTPRepo) MarkRecoveryCodeUsed(ctx context.Context, c *models.RecoveryCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for i := range m.codes[c.UserID] {
		if m.codes[c.UserID][i].ID == c.ID {
			if m.codes[c.UserID][i].UsedAt != nil {
				return repositories.ErrRecoveryCodeUsed
			}
			m.codes[c.UserID][i].UsedAt = &now
			c.UsedAt = &now
			return nil
		}
	}
	return repositories.ErrRecoveryCodeUsed
}

// ---- mock TOTP validator (for MFA login tests) ----

type mockTOTPValidator struct {
	mu    sync.Mutex
	err   error // what Validate should return
	calls int
}

func (m *mockTOTPValidator) Validate(ctx context.Context, userID uint, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.err
}

// ---- mock OAuth identity repo ----

type mockOAuthIdentityRepo struct {
	mu     sync.Mutex
	rows   []*models.OAuthIdentity
	nextID uint
}

func newMockOAuthIdentityRepo() *mockOAuthIdentityRepo { return &mockOAuthIdentityRepo{} }

func (m *mockOAuthIdentityRepo) Create(ctx context.Context, identity *models.OAuthIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	identity.ID = m.nextID
	identity.CreatedAt = time.Now()
	clone := *identity
	m.rows = append(m.rows, &clone)
	return nil
}

func (m *mockOAuthIdentityRepo) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.Provider == provider && r.ProviderUserID == providerUserID {
			c := *r
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockOAuthIdentityRepo) FindByUserIDAndProvider(ctx context.Context, userID uint, provider string) (*models.OAuthIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.UserID == userID && r.Provider == provider {
			c := *r
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockOAuthIdentityRepo) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// ---- mock Google ID token verifier (no real network/JWKS calls) ----

type mockGoogleIDTokenVerifier struct {
	mu     sync.Mutex
	claims *GoogleIDTokenClaims
	err    error
	tokens []string
}

func (m *mockGoogleIDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*GoogleIDTokenClaims, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = append(m.tokens, rawIDToken)
	if m.err != nil {
		return nil, m.err
	}
	c := *m.claims
	return &c, nil
}

// ---- mock Google OAuth client (skips consent URL + code exchange) ----

type mockGoogleOAuthClient struct {
	mu            sync.Mutex
	authURL       string
	token         *oauth2.Token
	err           error
	codes         []string
	lastChallenge string
	lastVerifier  string
}

func (m *mockGoogleOAuthClient) AuthCodeURL(state, codeChallenge string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastChallenge = codeChallenge
	return m.authURL + "?state=" + state + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256"
}

func (m *mockGoogleOAuthClient) Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes = append(m.codes, code)
	m.lastVerifier = codeVerifier
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

// ---- mock token issuer (stands in for AuthService in flow tests) ----

type mockTokenIssuer struct {
	mu      sync.Mutex
	pair    TokenPair
	profile UserProfile
	pending *MFAPendingResult
	err     error
	users   []*models.User
	details []string
}

func (m *mockTokenIssuer) CheckMFAOrIssueTokens(ctx context.Context, user *models.User, ip, ua, detail string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = append(m.users, user)
	m.details = append(m.details, detail)
	if m.err != nil {
		return TokenPair{}, UserProfile{}, nil, m.err
	}
	return m.pair, m.profile, m.pending, nil
}

var errNotFound = errNotFoundErr{}

type errNotFoundErr struct{}

func (errNotFoundErr) Error() string { return "not found" }
