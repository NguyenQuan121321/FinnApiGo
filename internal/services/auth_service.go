// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/device"
	"github.com/finnapigo/finnapigo/internal/geo"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/netutil"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/nbutton23/zxcvbn-go"
	"gorm.io/gorm"
)

// dummyHash is a pre-computed bcrypt hash of a static string. It is compared
// during login when the user doesn't exist, so the response time is
// indistinguishable from a wrong-password path. Generated once at init.
var dummyHash string

func init() {
	h, err := hash.HashPassword("dummy-timing-equalization")
	if err != nil {
		panic("auth: failed to generate dummy bcrypt hash: " + err.Error())
	}
	dummyHash = h
}

// AuthService holds all core-auth business logic. It depends only on repo
// interfaces + stateless helpers (jwt, hashing), so it is trivially unit-testable.
type AuthService struct {
	users         UserRepo
	tokens        RefreshTokenRepo
	usedTokens    UsedTokenRepo
	audits        AuditRepo
	store         store.Store
	jwt           *jwt.JWTManager
	cfg           config.AuthConfig
	rlCfg         config.RateLimitConfig // §2/§3 velocity + adaptive-captcha knobs
	jwtCfg        config.JWTConfig
	notify        Notifier
	captcha       CaptchaVerifier // §3 — nil-safe (NoOp when off)
	geo           geo.Resolver    // IP -> location label; nil-safe (Unknown)
	totpRepo      TOTPRepo        // nil-safe — MFA check skipped when nil
	totpValidator TOTPValidator   // nil-safe — MFA completion unavailable when nil
	// sessions persists the server-side session entity (P0.3). Nil-safe
	// (legacy tests): token issuance degrades to session-less rows and reuse
	// detection falls back to the documented global revocation.
	sessions SessionRepo
	// breached screens new passwords against known breach corpora (NIST
	// 800-63B). Nil-safe: no screening when not wired (see
	// WithBreachedPasswordChecker).
	breached *BreachedPasswordChecker
	// minPasswordScore defines the minimum zxcvbn score (P1.7, default 0 in tests, 3 in prod).
	minPasswordScore int
	passkeys         PasskeyRepo
	oauthIdents      OAuthIdentityRepo
	bcryptCost       int
	dummyHash        string
}

// AuthServiceOption customizes optional service capabilities without growing
// the positional constructor further.
type AuthServiceOption func(*AuthService)

// WithBcryptCost configures a custom bcrypt cost work factor (e.g. hash.MinCost for fast tests).
func WithBcryptCost(cost int) AuthServiceOption {
	return func(s *AuthService) {
		if cost >= hash.MinCost && cost <= hash.MaxCost {
			s.bcryptCost = cost
			dh, err := hash.HashPasswordWithCost("dummy-timing-equalization", cost)
			if err == nil {
				s.dummyHash = dh
			}
		}
	}
}

// UserService is an alias for AuthService, matching standard enterprise service naming.
type UserService = AuthService

// NewUserService is a constructor alias for NewAuthService.
var NewUserService = NewAuthService

// WithSessionRepo wires server-side session persistence (P0.3). Without it
// the service keeps the legacy behavior: refresh-token rows act as their own
// (unlinked) families and reuse detection revokes globally.
func WithSessionRepo(repo SessionRepo) AuthServiceOption {
	return func(s *AuthService) { s.sessions = repo }
}

// WithBreachedPasswordChecker wires the HIBP-style breached-password screener.
func WithBreachedPasswordChecker(c *BreachedPasswordChecker) AuthServiceOption {
	return func(s *AuthService) { s.breached = c }
}

// WithMinPasswordScore configures zxcvbn password strength scoring threshold (P1.7).
func WithMinPasswordScore(minScore int) AuthServiceOption {
	return func(s *AuthService) { s.minPasswordScore = minScore }
}

// WithAuthPasskeys wires PasskeyRepo for credential erasure upon GDPR right-to-erasure (P1.3).
func WithAuthPasskeys(p PasskeyRepo) AuthServiceOption {
	return func(s *AuthService) { s.passkeys = p }
}

// WithAuthOAuthIdents wires OAuthIdentityRepo for identity link erasure upon GDPR right-to-erasure (P1.3).
func WithAuthOAuthIdents(o OAuthIdentityRepo) AuthServiceOption {
	return func(s *AuthService) { s.oauthIdents = o }
}

// NewAuthService constructs the service. Repos are interfaces so mocks can be
// passed in tests. store may be nil (some features will be no-ops). rlCfg drives
// the §2/§3 velocity limiters and adaptive CAPTCHA; captcha may be nil.
// geoResolver may be nil (defaults to NoOp — all locations "Unknown").
// Options wire optional capabilities (breached-password screening).
func NewAuthService(
	users UserRepo,
	tokens RefreshTokenRepo,
	usedTokens UsedTokenRepo,
	audits AuditRepo,
	store store.Store,
	jwt *jwt.JWTManager,
	authCfg config.AuthConfig,
	rlCfg config.RateLimitConfig,
	jwtCfg config.JWTConfig,
	notify Notifier,
	captcha CaptchaVerifier,
	geoResolver geo.Resolver,
	totpRepo TOTPRepo,
	totpValidator TOTPValidator,
	opts ...AuthServiceOption,
) *AuthService {
	if captcha == nil {
		captcha = NoOpCaptchaVerifier{}
	}
	if geoResolver == nil {
		geoResolver = geo.NewNoOpResolver()
	}
	cost := authCfg.BcryptCost
	if cost < hash.MinCost || cost > hash.MaxCost {
		cost = hash.DefaultCost
	}
	s := &AuthService{
		users: users, tokens: tokens, usedTokens: usedTokens, audits: audits,
		store: store, jwt: jwt, cfg: authCfg, rlCfg: rlCfg, jwtCfg: jwtCfg,
		notify: notify, captcha: captcha, geo: geoResolver,
		totpRepo: totpRepo, totpValidator: totpValidator,
		bcryptCost: cost,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.bcryptCost == hash.DefaultCost {
		s.dummyHash = dummyHash
	} else {
		dh, err := hash.HashPasswordWithCost("dummy-timing-equalization", s.bcryptCost)
		if err != nil {
			s.dummyHash = dummyHash
		} else {
			s.dummyHash = dh
		}
	}
	return s
}

func (s *AuthService) hashPassword(plain string) (string, error) {
	return hash.HashPasswordWithCost(plain, s.BcryptCost())
}

func (s *AuthService) getDummyHash() string {
	if s.dummyHash != "" {
		return s.dummyHash
	}
	return dummyHash
}

// BcryptCost returns the configured bcrypt work factor.
func (s *AuthService) BcryptCost() int {
	if s.bcryptCost <= 0 {
		return hash.DefaultCost
	}
	return s.bcryptCost
}

// TransactionalCredentialChanger is an OPTIONAL UserRepo capability: the
// production GORM repository applies the whole credential-change sequence in
// ONE transaction. Minimal test mocks predate it and fall back to the
// sequential path in applyCredentialChange.
type TransactionalCredentialChanger interface {
	// CredentialChangeTx applies password hash + lockout reset + pwd-version
	// bump + refresh-token revocation atomically; revokeRefresh runs inside
	// the transaction.
	CredentialChangeTx(ctx context.Context, userID uint, hashedPassword string, revokeRefresh func(tx *gorm.DB) error) error
}

// TxScopedTokenRevoker is the matching OPTIONAL RefreshTokenRepo capability:
// revoking all of a user's refresh tokens inside a caller-provided
// transaction.
type TxScopedTokenRevoker interface {
	RevokeAllForUserTx(tx *gorm.DB, userID uint) error
}

// FirstPasswordSetter is an OPTIONAL UserRepo capability: a conditional
// UPDATE that sets the password hash only while it is still empty, closing
// the check-then-act race between two concurrent first-password setters.
type FirstPasswordSetter interface {
	SetFirstPassword(ctx context.Context, userID uint, hashedPassword string) (bool, error)
}

// applyCredentialChange runs the four writes that must survive together on a
// credential change: password hash, lockout reset, pwd-version bump (A7),
// and refresh-token revocation. With the transactional capability the whole
// sequence is atomic — a crash can never leave the password changed while an
// attacker's refresh token survives (the rotation CAS in Refresh is the
// SECOND line of defense, not the only one).
func (s *AuthService) applyCredentialChange(ctx context.Context, user *models.User, hashedPassword string) error {
	tc, okUser := s.users.(TransactionalCredentialChanger)
	tr, okTok := s.tokens.(TxScopedTokenRevoker)
	if okUser && okTok {
		err := tc.CredentialChangeTx(ctx, user.ID, hashedPassword, func(tx *gorm.DB) error {
			if err := tr.RevokeAllForUserTx(tx, user.ID); err != nil {
				return err
			}
			// P0.3 — the session families die in the same transaction, so a
			// crash can never leave a live session row for a dead credential.
			if s.sessions != nil {
				return s.sessions.RevokeAllForUserTx(tx, user.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}
		// The tx bumped pwd_version in SQL — drop the A7 cache so
		// AuthMiddleware sees the new version immediately.
		if s.store != nil {
			s.store.Delete(fmt.Sprintf("pwdver:%d", user.ID))
		}
		return nil
	}
	// Sequential fallback (test mocks without the capabilities).
	if err := s.users.UpdatePassword(ctx, user, hashedPassword); err != nil {
		return err
	}
	if err := s.users.ResetFailedAttempts(ctx, user); err != nil {
		return err
	}
	if err := s.bumpPwdVersion(ctx, user.ID); err != nil {
		return err
	}
	if err := s.tokens.RevokeAllForUser(ctx, user.ID); err != nil {
		return err
	}
	if s.sessions != nil {
		return s.sessions.RevokeAllForUser(ctx, user.ID)
	}
	return nil
}

// passwordBreached consults the breached-password screener. Nil checker →
// not breached (screening not wired); the checker itself fails OPEN on
// upstream outages — availability first, screening is defense-in-depth.
func (s *AuthService) passwordBreached(ctx context.Context, pw string) bool {
	return s.breached != nil && s.breached.Breached(ctx, pw)
}

// ----- 1. Register -----

// Register creates a new user account: validates complexity, rejects duplicate
// email/username, hashes the password, sends a verification email via the
// notifier (§1.1 — token is NO LONGER returned in the API response).
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (UserProfile, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	emailLocalPart := ""
	if parts := strings.Split(in.Email, "@"); len(parts) > 0 {
		emailLocalPart = parts[0]
	}
	if err := validatePassword(in.Password, s.minPasswordScore, in.Username, emailLocalPart); err != nil {
		return UserProfile{}, err
	}
	// NIST 800-63B — screen new passwords against known breach corpora. The
	// checker fails OPEN on outage (see BreachedPasswordChecker).
	if s.passwordBreached(ctx, in.Password) {
		return UserProfile{}, ErrPasswordBreached
	}

	// §2 — registration velocity limiting (per-IP). Thwarts scripted mass
	// account creation regardless of the per-endpoint rate limiter in the
	// middleware. Uses the store so this is shared across instances. The IP
	// is collapsed to its /64 prefix for IPv6 so one host cycling addresses
	// inside its subnet cannot mint unbounded counter keys.
	if s.store != nil && in.IP != "" {
		key := ipCounterKey("reg:ip:", in.IP)
		count := s.store.IncrBy(key, 1, s.rlCfg.RegisterWindow)
		if count > int64(s.rlCfg.RegisterPerIPMax) {
			return UserProfile{}, ErrRateLimited
		}
	}

	// §2 — reject known disposable/throwaway email providers.
	if isDisposableEmail(in.Email) {
		return UserProfile{}, ErrDisposableEmail
	}

	// uniqueness checks (email + username) — P0.1 uniform anti-enum response
	if existing, err := s.users.FindByEmail(ctx, in.Email); err != nil {
		return UserProfile{}, fmt.Errorf("register: find email: %w", err)
	} else if existing != nil {
		return s.handleDuplicateRegistration(ctx, existing.Email, in.IP, in.Username)
	}
	if existing, err := s.users.FindByUsername(ctx, in.Username); err != nil {
		return UserProfile{}, fmt.Errorf("register: find username: %w", err)
	} else if existing != nil {
		return s.handleDuplicateRegistration(ctx, existing.Email, in.IP, in.Username)
	}

	hashed, err := s.hashPassword(in.Password)
	if err != nil {
		return UserProfile{}, err
	}

	user := &models.User{
		Username: in.Username,
		Email:    in.Email,
		Password: hashed,
		FullName: in.FullName,
		Role:     models.RoleUser,
		IsActive: true,
	}
	// §1.7 / P0.1 — TOCTOU race: two concurrent registers with the same email/username
	// can both pass the existence checks. If the DB rejects with duplicate-key,
	// deliver the neutral anti-enumeration response rather than failing with 500.
	if err := s.users.Create(ctx, user); err != nil {
		if isMySQLDup(err) {
			return s.handleDuplicateRegistration(ctx, in.Email, in.IP, in.Username)
		}
		return UserProfile{}, err
	}

	// §1.1 — Issue a verification JWT and deliver it via the notifier.
	// The token is NEVER returned to the client — the user must prove
	// control of their inbox to self-verify.
	verifyToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
	if err != nil {
		return UserProfile{}, err
	}
	// C11 — the user row is already committed; a failed email delivery must
	// not turn the registration into a 500 (a client retry then collides with
	// ErrEmailExists). Degrade to success + error log + audit; the
	// resend-verification endpoint is the recovery path.
	if s.notify != nil {
		if err := s.notify.SendEmailVerification(ctx, user.Email, verifyToken); err != nil {
			slog.Error("register: verification email delivery failed",
				"user_id", user.ID, "email", user.Email, "err", err)
			uid := user.ID
			s.audits.Record(ctx, &models.AuditLog{
				UserID: &uid, Email: user.Email,
				Event: models.AuditEventVerifyEmailSendFailed, Success: false,
				Detail: err.Error(), IPAddress: in.IP,
			})
		}
	}
	return FromUser(user), nil
}

// handleDuplicateRegistration logs the attempt, fires a throttled notification
// email to the existing account owner, and returns a neutral UserProfile (201)
// so attackers cannot probe for registered emails/usernames (P0.1 anti-enumeration).
func (s *AuthService) handleDuplicateRegistration(ctx context.Context, ownerEmail, ip, attemptedUsername string) (UserProfile, error) {
	s.audits.Record(ctx, &models.AuditLog{
		Event:     models.AuditEventRegisterDuplicate,
		Email:     ownerEmail,
		IPAddress: ip,
		Success:   false,
		Detail:    fmt.Sprintf("attempted registration with existing email or username (attempted username: %s)", attemptedUsername),
	})
	// Layered throttling: reuse verify-resend global, per-IP, and per-email caps
	// so duplicate registration attempts cannot be weaponized into an email-bombing oracle.
	if s.shouldThrottleDuplicateRegisterAlert(ownerEmail, ip) {
		slog.Warn("register: duplicate alert suppressed by rate limit", "email", ownerEmail, "ip", ip)
	} else if s.notify != nil {
		go func() {
			defer func() { _ = recover() }()
			alertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), newIPAlertTimeout)
			defer cancel()
			if err := s.notify.SendDuplicateRegisterAlert(alertCtx, ownerEmail); err != nil {
				slog.Warn("register: duplicate alert send failed", "email", ownerEmail, "err", err)
			}
		}()
	}
	// Return neutral synthetic profile (HTTP 201 Created)
	return UserProfile{
		Username:        attemptedUsername,
		Email:           ownerEmail,
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: false,
		CreatedAt:       time.Now().UTC(),
	}, nil
}

func (s *AuthService) shouldThrottleDuplicateRegisterAlert(email, ip string) bool {
	if s.store == nil {
		return false
	}
	// 1. Global cap
	if s.rlCfg.VerifyResendGlobalMax > 0 {
		if n := s.store.IncrBy("reg:dup:global", 1, s.rlCfg.VerifyResendGlobalWindow); n > int64(s.rlCfg.VerifyResendGlobalMax) {
			return true
		}
	}
	// 2. Per-IP cap
	if ip != "" && s.rlCfg.VerifyResendPerIPMax > 0 {
		if n := s.store.IncrBy(ipCounterKey("reg:dup:ip:", ip), 1, s.rlCfg.VerifyResendPerIPWindow); n > int64(s.rlCfg.VerifyResendPerIPMax) {
			return true
		}
	}
	// 3. Per-email cap
	if email != "" && s.rlCfg.VerifyResendPerEmailMax > 0 {
		if n := s.store.IncrBy("reg:dup:email:"+email, 1, s.rlCfg.VerifyResendWindow); n > int64(s.rlCfg.VerifyResendPerEmailMax) {
			return true
		}
	}
	return false
}

// ----- 2. Login -----

// Login authenticates credentials, applies lockout logic, and returns a fresh
// access + refresh token pair — unless the user has TOTP enabled, in which case
// it returns a short-lived mfa_pending token and a nil TokenPair so the handler
// can prompt for a second factor before issuing real tokens.
func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	// §3 — per-account login velocity limit: throttle repeated attempts against
	// one email even when spread across many IPs. C9: only FAILED attempts
	// count — this check reads the counter without incrementing, failures grow
	// it, and a successful login clears it (the owner typing the correct
	// password must not be throttled by their own earlier typos).
	if s.store != nil && email != "" && s.rlCfg.LoginPerAccountMax > 0 {
		if storeCounterValue(s.store, "login:acct:"+email) >= int64(s.rlCfg.LoginPerAccountMax) {
			return TokenPair{}, UserProfile{}, nil, ErrRateLimited
		}
	}

	// §3 — adaptive CAPTCHA: after N failed login attempts from one IP, require
	// a valid CAPTCHA token before proceeding. This blocks credential-stuffing
	// tools that rotate IPs to avoid per-IP rate limits. The counter MUST be
	// read through storeCounterValue: Redis hands counters back as STRINGS, and
	// a bare int64 type assertion silently reads every Redis counter as 0 —
	// the gate would never fire in multi-instance mode.
	if s.captcha != nil && s.store != nil && s.rlCfg.LoginCaptchaAfterFails > 0 {
		if storeCounterValue(s.store, ipCounterKey("loginfail:", ip)) >= int64(s.rlCfg.LoginCaptchaAfterFails) {
			if err := s.captcha.Verify(ctx, in.CaptchaToken); err != nil {
				return TokenPair{}, UserProfile{}, nil, ErrCaptchaRequired
			}
		}
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, fmt.Errorf("login: find user: %w", err)
	}
	// §1.6 — Timing side-channel mitigation: when user == nil, still run a
	// bcrypt comparison against a dummy hash so both code paths take ~equal
	// time (~100-300ms). The error message is identical either way.
	if user == nil {
		hash.CheckPassword(s.getDummyHash(), in.Password)
		s.recordLoginFailIP(ctx, ip)
		s.recordLoginFailAccount(email)
		LoginFailures.Add(1)
		s.audits.Record(ctx, loginFailedEvent(nil, email, ip, "unknown user"))
		return TokenPair{}, UserProfile{}, nil, ErrInvalidCredentials
	}

	// §2 — optional email-verification gate. When RequireEmailVerified is
	// true, unverified accounts cannot log in. Default false to avoid breaking
	// existing UX; the CHANGELOG and README document this as a policy decision.
	if s.cfg.RequireEmailVerified && !user.IsEmailVerified {
		return TokenPair{}, UserProfile{}, nil, ErrEmailNotVerified
	}

	if !user.IsActive {
		LoginFailures.Add(1)
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "disabled"))
		return TokenPair{}, UserProfile{}, nil, ErrAccountDisabled
	}

	if locked := s.isLocked(user); locked {
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "locked"))
		return TokenPair{}, UserProfile{}, nil, ErrAccountLocked
	}

	// The password comparison also equalizes timing for OAuth-only accounts:
	// they hold Password == "" and a direct bcrypt call against "" fails in
	// microseconds — a clean enumeration oracle ("email exists, Google-only").
	// Run the dummy-hash compare for that shape so the response time matches
	// the wrong-password path.
	passwordMatches := false
	if user.Password != "" {
		passwordMatches = hash.CheckPassword(user.Password, in.Password)
	} else {
		hash.CheckPassword(s.getDummyHash(), in.Password)
	}
	if !passwordMatches {
		LoginFailures.Add(1)
		s.recordFailedLogin(ctx, user, email, ip)
		return TokenPair{}, UserProfile{}, nil, ErrInvalidCredentials
	}

	// success: reset counter
	if err := s.users.ResetFailedAttempts(ctx, user); err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	// C9 — clear the per-account velocity counter too: the owner proving the
	// correct password must not stay throttled by their own earlier typos.
	if s.store != nil {
		s.store.Delete("login:acct:" + email)
	}

	return s.CheckMFAOrIssueTokens(ctx, user, ip, ua, "")
}

// ----- 2b. Complete MFA Login -----

// CompleteMFALogin validates the TOTP code for a user who has already passed
// password authentication (proven by a valid mfa_pending JWT). On success it
// issues the real access+refresh token pair and creates the session/device DB
// record. The TOTP validation is delegated to the injected TOTPValidator,
// reusing the exact same logic as the existing /totp/validate endpoint.
func (s *AuthService) CompleteMFALogin(ctx context.Context, in CompleteMFALoginInput) (TokenPair, UserProfile, error) {
	if s.totpValidator == nil {
		return TokenPair{}, UserProfile{}, ErrInvalidToken
	}

	if err := s.totpValidator.Validate(ctx, in.UserID, in.Code); err != nil {
		return TokenPair{}, UserProfile{}, err
	}

	user, err := s.users.FindByID(ctx, in.UserID)
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, UserProfile{}, ErrInvalidToken
	}

	pair, err := s.issueTokenPair(ctx, user, in.IP, in.UA, "")
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventLogin,
		IPAddress: in.IP, Success: true, Detail: "mfa-complete",
	})
	return pair, FromUser(user), nil
}

// ----- 2c. Shared MFA + token issuance helper ----

// CheckMFAOrIssueTokens checks whether the user has TOTP enabled. If so it
// issues a short-lived mfa_pending JWT; otherwise it issues a full access +
// refresh token pair and records a login audit event. This is called from both
// the password Login path and the Google OAuth callback path so the MFA
// enforcement logic is never duplicated.
//
// auditDetail is an optional label for the audit row (e.g. "" for password,
// "google-oauth" for Google sign-in).
func (s *AuthService) CheckMFAOrIssueTokens(ctx context.Context, user *models.User, ip, ua, auditDetail string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	// The password check passed — count the login as a credential success
	// regardless of which branch below completes it (O3).
	LoginSuccesses.Add(1)
	// ---- MFA enforcement: check if TOTP is active for this user ----
	// When totpRepo is nil (e.g. legacy tests), skip the check entirely so
	// the login flow is unchanged for users without TOTP wired.
	if s.totpRepo != nil {
		device, err := s.totpRepo.FindByUserID(ctx, user.ID)
		if err != nil {
			return TokenPair{}, UserProfile{}, nil, fmt.Errorf("login: check totp: %w", err)
		}
		if device != nil && device.Enabled {
			// TOTP is active — issue a short-lived mfa_pending token carrying
			// only uid + type (no role/permissions). The user must complete
			// MFA via /mfa/login-verify to receive real tokens.
			mfaToken, err := s.jwt.Issue(user.ID, "", "",
				jwt.TokenTypeMFAPending, s.jwtCfg.MFAPendingTTL)
			if err != nil {
				return TokenPair{}, UserProfile{}, nil, err
			}
			return TokenPair{}, UserProfile{}, &MFAPendingResult{
				MFARequired: true,
				MFAToken:    mfaToken,
			}, nil
		}
	}

	pair, err := s.issueTokenPair(ctx, user, ip, ua, "")
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventLogin,
		IPAddress: ip, Success: true, Detail: auditDetail,
	})
	return pair, FromUser(user), nil, nil
}

// ----- 3. Logout -----

// Logout revokes the supplied refresh token AND its session family, and
// denylists the caller's access-token jti for the token's remaining lifetime
// (P0.2 — before this, the access token stayed valid until its exp). The
// accessJTI comes from AuthMiddleware's context; an empty value (legacy
// token) degrades to refresh-token-only revocation. Idempotent — revoking an
// already-revoked or unknown token is not an error, to avoid leaking state.
func (s *AuthService) Logout(ctx context.Context, refreshToken, accessJTI, ip string) error {
	// P0.2 — the caller's own access token dies NOW, regardless of what the
	// refresh-token lookup below finds.
	s.denylistAccessToken(accessJTI)

	hash := hash.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("logout: find token: %w", err)
	}
	if rt == nil || rt.Revoked {
		return nil
	}
	// A concurrent revocation (rotation race) also leaves the session dead —
	// Logout's contract is idempotent, so that outcome is still success here.
	if err := s.tokens.Revoke(ctx, rt); err != nil && !errors.Is(err, repositories.ErrTokenAlreadyRevoked) {
		return err
	}
	// Kill the whole family the token belongs to: the session row (so it
	// disappears from the device list), its remaining refresh tokens, and a
	// sid denylist entry so sibling ACCESS tokens die before their exp.
	if rt.SessionID != "" && s.sessions != nil {
		if sess, serr := s.sessions.FindByID(ctx, rt.SessionID); serr == nil {
			_ = s.sessions.RevokeByID(ctx, rt.SessionID, rt.UserID)
			_ = s.tokens.RevokeBySession(ctx, rt.SessionID)
			s.denylistSession(sess)
		}
	}
	uid := rt.UserID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: models.AuditEventLogout, IPAddress: ip, Success: true,
	})
	if accessJTI != "" {
		s.audits.Record(ctx, &models.AuditLog{
			UserID: &uid, Event: models.AuditEventAccessTokenRevoked,
			IPAddress: ip, Success: true, Detail: "logout denylisted access jti",
		})
	}
	return nil
}

// ----- 3b. LogoutAll -----

// LogoutAll revokes every active session family for the authenticated user —
// a "sign out everywhere" action (§4) — and bumps the password version (A7)
// so outstanding ACCESS tokens are rejected by AuthMiddleware immediately,
// not at their exp (P0.2).
func (s *AuthService) LogoutAll(ctx context.Context, userID uint, ip string) error {
	if err := s.tokens.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	if s.sessions != nil {
		if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
			return err
		}
	}
	if err := s.bumpPwdVersion(ctx, userID); err != nil {
		return fmt.Errorf("logout-all: bump pwd version: %w", err)
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &userID, Event: models.AuditEventLogout, IPAddress: ip,
		Success: true, Detail: "logout-all",
	})
	return nil
}

// ----- 4. Refresh token (rotation) -----

// Refresh validates the presented refresh token, revokes it, and issues a NEW
// access + refresh pair (rotation) inside the SAME session family. Reuse of
// an already-revoked token is a theft signal: with sessions wired (P0.3) only
// that session's chain dies — the user's OTHER devices keep working — and the
// owner is notified. Legacy session-less rows fall back to the documented
// global revocation. The caller's ip/ua are stamped onto the family and used
// for audit events.
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string) (TokenPair, error) {
	hash := hash.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: find token: %w", err)
	}

	if rt == nil {
		return TokenPair{}, ErrInvalidToken
	}

	// §Session — a revoked chain can NEVER rotate. Block instantly and treat
	// it as a reuse/theft signal: revoke the affected family (P0.3 isolation)
	// and record a high-severity audit event.
	if rt.Revoked {
		TokenReuseDetections.Add(1)
		s.handleTokenReuse(ctx, rt, ip, "revoked refresh token presented")
		return TokenPair{}, ErrInvalidToken
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.tokens.Revoke(ctx, rt)
		return TokenPair{}, ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, ErrInvalidToken
	}

	// A token whose session family was revoked separately (user pressed
	// "revoke device", or a sibling rotation already killed the chain) is
	// equally dead — presenting it is reuse of a revoked family.
	if rt.SessionID != "" && s.sessions != nil {
		sess, err := s.sessions.FindByID(ctx, rt.SessionID)
		if err != nil {
			return TokenPair{}, fmt.Errorf("refresh: find session: %w", err)
		}
		if sess == nil {
			return TokenPair{}, ErrInvalidToken
		}
		if sess.Revoked || time.Now().After(sess.ExpiresAt) {
			TokenReuseDetections.Add(1)
			s.handleTokenReuse(ctx, rt, ip, "revoked session presented")
			return TokenPair{}, ErrInvalidToken
		}
	}

	// Rotate: revoke the old, issue a new pair INSIDE the same family
	// (carrying the caller's device metadata so the "sessions" list reflects
	// the rotating device). Revoke is a compare-and-set — losing the race
	// means a concurrent request already consumed this token, which is reuse
	// by definition (C1).
	if err := s.tokens.Revoke(ctx, rt); err != nil {
		if errors.Is(err, repositories.ErrTokenAlreadyRevoked) {
			TokenReuseDetections.Add(1)
			s.handleTokenReuse(ctx, rt, ip, "concurrent refresh lost revoke race")
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}
	pair, err := s.issueTokenPair(ctx, user, ip, ua, rt.SessionID)
	if err != nil {
		return TokenPair{}, err
	}
	RefreshRotations.Add(1)
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventRefreshToken, IPAddress: ip, Success: true,
	})
	return pair, nil
}

// handleTokenReuse contains the P0.3 isolation policy: when the reused token
// belongs to a session family, kill ONLY that family (session row + its
// refresh-token chain + a sid denylist entry killing its outstanding access
// tokens) and notify the owner; legacy session-less rows keep the documented
// global revocation. Failures are best-effort — the caller already rejected
// the request; this is containment + forensics.
func (s *AuthService) handleTokenReuse(ctx context.Context, rt *models.RefreshToken, ip, detail string) {
	if rt.SessionID != "" && s.sessions != nil {
		sess, err := s.sessions.FindByID(ctx, rt.SessionID)
		if err != nil {
			slog.Error("refresh: reuse containment lookup failed", "session_id", rt.SessionID, "err", err)
		}
		if err := s.sessions.RevokeByID(ctx, rt.SessionID, rt.UserID); err != nil &&
			!errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Error("refresh: reuse containment revoke failed", "session_id", rt.SessionID, "err", err)
		}
		if err := s.tokens.RevokeBySession(ctx, rt.SessionID); err != nil {
			slog.Error("refresh: reuse containment token revoke failed", "session_id", rt.SessionID, "err", err)
		}
		s.denylistSession(sess)
		s.audits.Record(ctx, &models.AuditLog{
			UserID: &rt.UserID, Event: models.AuditEventTokenReuse,
			IPAddress: ip, Success: false, Detail: detail + " (session family revoked)",
		})
		if sess != nil {
			s.notifySecurityAsync(ctx, rt.UserID, "Suspicious sign-in activity detected",
				"A refresh token from one of your devices was reused after being revoked. That device's session has been ended. If this was not you, change your password immediately.")
		}
		return
	}
	// Legacy row (pre-0003 migration): no family to isolate — the old policy
	// applies. The sid-less access tokens die via their own exp.
	_ = s.tokens.RevokeAllForUser(ctx, rt.UserID)
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &rt.UserID, Event: models.AuditEventTokenReuse,
		IPAddress: ip, Success: false, Detail: detail,
	})
}

// notifySecurityAsync delivers a security-transparency email off the request
// path (bounded timeout, never panics, never blocks the caller). The lookup
// is best-effort: an owner who cannot be found simply is not notified — the
// audit row is the durable record.
func (s *AuthService) notifySecurityAsync(ctx context.Context, userID uint, event, body string) {
	if s.notify == nil {
		return
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil || user == nil || user.Email == "" {
		return
	}
	to := user.Email
	go func() {
		defer func() { _ = recover() }() // a notification must never kill a request goroutine
		alertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), newIPAlertTimeout)
		defer cancel()
		if err := s.notify.SendSecurityAlert(alertCtx, to, event, body); err != nil {
			slog.Warn("security alert delivery failed", "user_id", userID, "event", event, "err", err)
		}
	}()
}

// ----- 5. Forgot password -----

// ForgotPassword generates a password-reset JWT and delivers it via the
// notifier. It NEVER reveals whether the email exists — it returns nil for
// unknown users so the handler can return an identical message.
func (s *AuthService) ForgotPassword(ctx context.Context, email, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("forgot-password: find user: %w", err)
	}
	if user == nil {
		// Timing equalization: a known email costs a bcrypt compare plus an
		// SMTP round-trip; the dummy compare closes the cheap "return
		// immediately" oracle. SMTP latency dominates the remainder — the
		// identical-status response does the rest.
		hash.CheckPassword(s.getDummyHash(), "forgot-password-timing-equalization")
		return nil
	}
	resetToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeReset, s.jwtCfg.ResetTTL)
	if err != nil {
		return err
	}
	if err := s.notify.SendPasswordReset(ctx, email, resetToken); err != nil {
		return fmt.Errorf("forgot-password: send: %w", err)
	}
	return nil
}

// ----- 5b. Resend verification email -----

// ResendVerifyEmail issues a fresh type=verify-email JWT and delivers it via
// the notifier. It NEVER reveals whether the email exists or is already
// verified — unknown/verified/disposable/blocked all surface identically
// (anti-enumeration, ASVS v4.0-2.1.1) except ErrRateLimited, which lets a
// legitimate client back off.
//
// Defense-in-depth layering (each layer short-circuits before the next, and
// every store-backed layer is shared across instances via the store.Store):
//  1. per-IP middleware limiter (process-local, cheap first filter)
//  2. GLOBAL volume cap — circuit-breaker vs botnet floods rotating IPs+emails
//  3. per-IP service throttle — store-backed, survives IP rotation
//  4. disposable-domain rejection — O(1) lookup before any DB hit
//  5. per-email throttle — stops repeat bombing of one inbox
//  6. FindByEmail → issue JWT → notify
//
// All rate-limit trips and disposable rejections are recorded as audit events
// (ASVS v4.0-7.3.1) for SOC visibility.
func (s *AuthService) ResendVerifyEmail(ctx context.Context, email, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	// Layer 2 (§7.6.3) — GLOBAL volume cap: the only control that stops an
	// attacker rotating BOTH IPs and emails (per-key limiters cannot). Acts as
	// a hard circuit-breaker on the entire resend endpoint.
	if s.store != nil && s.rlCfg.VerifyResendGlobalMax > 0 {
		if n := s.store.IncrBy("verify:resend:global", 1, s.rlCfg.VerifyResendGlobalWindow); n > int64(s.rlCfg.VerifyResendGlobalMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "global cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 3 (§7.6.3) — per-IP service throttle. Store-backed, so unlike the
	// in-process middleware limiter it is shared across instances and survives
	// IP rotation toward a single target inbox.
	if s.store != nil && ip != "" && s.rlCfg.VerifyResendPerIPMax > 0 {
		if n := s.store.IncrBy(ipCounterKey("verify:resend:ip:", ip), 1, s.rlCfg.VerifyResendPerIPWindow); n > int64(s.rlCfg.VerifyResendPerIPMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "per-ip cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 4 (§2.1.1) — disposable-domain rejection at the source. Reuses the
	// existing isDisposableEmail O(1) lookup; runs BEFORE the DB query. Returns
	// nil (success-like) so an attacker cannot probe which addresses are blocked.
	if isDisposableEmail(email) {
		s.audits.Record(ctx, &models.AuditLog{
			Event: models.AuditEventVerifyResendBlocked, Email: email,
			IPAddress: ip, Success: false, Detail: "disposable domain",
		})
		return nil
	}

	// Layer 5 — per-email throttle: stops repeat bombing of a single inbox.
	if s.store != nil && email != "" && s.rlCfg.VerifyResendPerEmailMax > 0 {
		key := "verify:resend:" + email
		count := s.store.IncrBy(key, 1, s.rlCfg.VerifyResendWindow)
		if count > int64(s.rlCfg.VerifyResendPerEmailMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "per-email cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 6 — lookup, issue, notify.
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("resend-verify: find user: %w", err)
	}
	// Anti-enumeration: unknown email -> nil (handler emits the same message).
	if user == nil {
		return nil
	}
	// Already verified -> no-op (no redundant email), still nil.
	if user.IsEmailVerified {
		return nil
	}

	verifyToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
	if err != nil {
		return err
	}
	if err := s.notify.SendEmailVerification(ctx, user.Email, verifyToken); err != nil {
		return fmt.Errorf("resend-verify: send: %w", err)
	}
	return nil
}

// ----- 6. Reset password -----

// ResetPassword verifies the reset JWT and sets the new password. The JWT
// carries type=reset so it cannot be replayed as an access token.
// §1.8 — single-use enforcement via jti (SetNX).
func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput, ip string) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != jwt.TokenTypeReset {
		return ErrInvalidToken
	}
	user, err := s.users.FindByID(ctx, claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	emailLocalPart := ""
	if parts := strings.Split(user.Email, "@"); len(parts) > 0 {
		emailLocalPart = parts[0]
	}
	if err := validatePassword(in.NewPassword, s.minPasswordScore, user.Username, emailLocalPart); err != nil {
		return err
	}
	if s.passwordBreached(ctx, in.NewPassword) {
		return ErrPasswordBreached
	}

	// §1.8 — single-use enforcement: check-and-mark the jti atomically, with
	// the durable used_tokens table backstopping a store flush (C8). A
	// failed durable backstop is FAIL-CLOSED (see markTokenDurable).
	if !s.consumeSingleUseToken(ctx, claims.ID, s.jtiStoreTTL(claims)) {
		return ErrInvalidToken
	}
	if err := s.markTokenDurable(ctx, claims.ID, jwt.TokenTypeReset, user.ID, claims.ExpiresAt.Time); err != nil {
		return err
	}

	hashed, err := s.hashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	// C10 — the reset proves account ownership: clear any attacker-sustained
	// lockout. A7 — kill outstanding ACCESS tokens. Both land in the SAME
	// transaction as the password update and the refresh-token revocation, so
	// a crash can never leave the password changed while an attacker's
	// sessions survive (the rotation CAS is the last line of defense, not the
	// only one).
	if err := s.applyCredentialChange(ctx, user, hashed); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordReset,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 7. Change password -----

// ChangePassword verifies the old password before accepting the new one, then
// revokes all existing refresh tokens (so all other sessions must log in again).
func (s *AuthService) ChangePassword(ctx context.Context, in ChangePasswordInput, ip string) error {
	user, err := s.users.FindByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if !hash.CheckPassword(user.Password, in.OldPassword) {
		return ErrInvalidCredentials
	}
	emailLocalPart := ""
	if parts := strings.Split(user.Email, "@"); len(parts) > 0 {
		emailLocalPart = parts[0]
	}
	if err := validatePassword(in.NewPassword, s.minPasswordScore, user.Username, emailLocalPart); err != nil {
		return err
	}
	if s.passwordBreached(ctx, in.NewPassword) {
		return ErrPasswordBreached
	}
	hashed, err := s.hashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	// C10 — knowing the old password proves ownership: clear lockout state.
	// A7 — kill outstanding ACCESS tokens. Both land in the SAME transaction
	// as the password update and the refresh-token revocation (see
	// applyCredentialChange) so a partial failure can never strand an
	// attacker session on the far side of a password change.
	if err := s.applyCredentialChange(ctx, user, hashed); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordChanged,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 7b. Set password (first password for OAuth-only accounts) -----
//
// INVESTIGATION NOTES (pre-implementation findings):
//   - Exact "no password set" condition: models.User.Password is a NOT NULL
//     string column holding a bcrypt hash for password-registered users, and
//     OAuthService.createGoogleUser creates Google-only accounts with
//     Password == "" (empty string — never NULL, never a dummy hash). So
//     user.Password == "" is the precise marker of an account that has never
//     had a usable password.
//   - Reused helpers (no duplication): the package-private validatePassword
//     in this file for strength rules, and hash.HashPassword (bcrypt,
//     DefaultCost) for hashing, persisted via UserRepo.UpdatePassword — the
//     identical code path used by Register / ResetPassword / ChangePassword.
//
// SetPassword establishes a FIRST password for an account created via Google
// OAuth. It is deliberately distinct from ChangePassword: there is no
// oldPassword to verify because the account has never had one. The core
// security boundary is the guard below — an account that already has a
// usable password is hard-rejected so this endpoint can never become a
// change-password bypass. The guard lives in the SERVICE layer (not only in
// the handler) so any future caller of this method inherits the protection.
func (s *AuthService) SetPassword(ctx context.Context, userID uint, newPassword, ip string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	// Only accounts WITHOUT a usable password may proceed. Everything else
	// must use ChangePassword, which verifies the old password first.
	if user.Password != "" {
		return ErrPasswordAlreadySet
	}
	emailLocalPart := ""
	if parts := strings.Split(user.Email, "@"); len(parts) > 0 {
		emailLocalPart = parts[0]
	}
	if err := validatePassword(newPassword, s.minPasswordScore, user.Username, emailLocalPart); err != nil {
		return err
	}
	if s.passwordBreached(ctx, newPassword) {
		return ErrPasswordBreached
	}
	hashed, err := s.hashPassword(newPassword)
	if err != nil {
		return err
	}
	// Conditional write: the UPDATE only matches rows whose password is still
	// empty, so two concurrent first-setters cannot both win (last-writer-wins
	// is closed). Losers get ErrPasswordAlreadySet.
	if fps, ok := s.users.(FirstPasswordSetter); ok {
		set, err := fps.SetFirstPassword(ctx, user.ID, hashed)
		if err != nil {
			return err
		}
		if !set {
			return ErrPasswordAlreadySet
		}
	} else if err := s.users.UpdatePassword(ctx, user, hashed); err != nil {
		// Legacy mock fallback (pre-capability test fakes).
		return err
	}
	// A7 — a first credential invalidates pre-credential access tokens.
	if err := s.bumpPwdVersion(ctx, user.ID); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventPasswordSet,
		IPAddress: ip, Success: true, Detail: "first password set (oauth-only account)",
	})
	return nil
}

// ----- 8. Me -----

// Me returns the sanitized profile for the authenticated user.
func (s *AuthService) Me(ctx context.Context, userID uint) (UserProfile, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return UserProfile{}, err
	}
	if user == nil {
		return UserProfile{}, ErrUserNotFound
	}
	return FromUser(user), nil
}

// GetUserAuditLog returns paginated, sanitized security events for the caller (P1.4).
func (s *AuthService) GetUserAuditLog(ctx context.Context, userID uint, page, limit int) ([]UserAuditLogItem, int64, error) {
	if s.audits == nil {
		return []UserAuditLogItem{}, 0, nil
	}
	logs, total, err := s.audits.FindByUserIDPaginated(ctx, userID, page, limit)
	if err != nil {
		return nil, 0, err
	}
	items := make([]UserAuditLogItem, len(logs))
	for i, l := range logs {
		items[i] = UserAuditLogItem{
			ID:        l.ID,
			Event:     l.Event,
			IPAddress: l.IPAddress,
			Success:   l.Success,
			CreatedAt: l.CreatedAt,
		}
	}
	return items, total, nil
}

// RequestChangeEmail initiates the email change ceremony (P1.2).
// Verifies password, validates disposable-email and collision checks,
// stages a 1h token in the store, sends verification to new email, and alert to old email.
func (s *AuthService) RequestChangeEmail(ctx context.Context, userID uint, in ChangeEmailRequestInput, ip string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if !hash.CheckPassword(user.Password, in.Password) {
		return ErrInvalidCredentials
	}

	newEmail := strings.ToLower(strings.TrimSpace(in.NewEmail))
	if newEmail == "" || newEmail == user.Email {
		return ErrInvalidInput
	}
	// Layered throttle BEFORE any notification leaves the process (distinct
	// key namespace, same VerifyResend* knobs): change-email sends to BOTH
	// the old and the new address, so a compromised session must not become
	// an email-bombing oracle against arbitrary inboxes.
	if s.store != nil {
		if s.rlCfg.VerifyResendGlobalMax > 0 {
			if n := s.store.IncrBy("chgemail:global", 1, s.rlCfg.VerifyResendGlobalWindow); n > int64(s.rlCfg.VerifyResendGlobalMax) {
				s.audits.Record(ctx, &models.AuditLog{
					UserID: &user.ID, Email: user.Email, Event: models.AuditEventEmailChangeRequested,
					IPAddress: ip, Success: false, Detail: "blocked: global cap",
				})
				return ErrRateLimited
			}
		}
		if ip != "" && s.rlCfg.VerifyResendPerIPMax > 0 {
			if n := s.store.IncrBy(ipCounterKey("chgemail:ip:", ip), 1, s.rlCfg.VerifyResendPerIPWindow); n > int64(s.rlCfg.VerifyResendPerIPMax) {
				s.audits.Record(ctx, &models.AuditLog{
					UserID: &user.ID, Email: user.Email, Event: models.AuditEventEmailChangeRequested,
					IPAddress: ip, Success: false, Detail: "blocked: per-ip cap",
				})
				return ErrRateLimited
			}
		}
		if s.rlCfg.VerifyResendPerEmailMax > 0 {
			if n := s.store.IncrBy("chgemail:email:"+user.Email, 1, s.rlCfg.VerifyResendWindow); n > int64(s.rlCfg.VerifyResendPerEmailMax) {
				s.audits.Record(ctx, &models.AuditLog{
					UserID: &user.ID, Email: user.Email, Event: models.AuditEventEmailChangeRequested,
					IPAddress: ip, Success: false, Detail: "blocked: per-email cap",
				})
				return ErrRateLimited
			}
		}
	}
	if isDisposableEmail(newEmail) {
		return ErrDisposableEmail
	}
	existing, err := s.users.FindByEmail(ctx, newEmail)
	if err != nil {
		return err
	}
	if existing != nil {
		return ErrEmailExists
	}

	token := uuid.New().String()
	storeKey := "change_email:" + token
	payload := fmt.Sprintf("%d:%s:%s", user.ID, user.Email, newEmail)
	if s.store != nil {
		s.store.Set(storeKey, payload, time.Hour)
	}

	if s.notify != nil {
		_ = s.notify.SendEmailVerification(ctx, newEmail, token)
		_ = s.notify.SendSecurityAlert(ctx, user.Email, "email_change_requested", fmt.Sprintf("A request was made to change your email address to %s. If you did not make this request, secure your account immediately.", newEmail))
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     user.Email,
			Event:     models.AuditEventEmailChangeRequested,
			IPAddress: ip,
			Success:   true,
			Detail:    "staged change to " + newEmail,
		})
	}
	return nil
}

// ConfirmChangeEmail completes the email change ceremony (P1.2).
// Consumes the staged token, re-checks collision, updates the email in DB,
// revokes all existing sessions/tokens, bumps pwd_version, and sends confirmation to old email.
func (s *AuthService) ConfirmChangeEmail(ctx context.Context, token, ip string) error {
	if s.store == nil || token == "" {
		return ErrInvalidToken
	}
	storeKey := "change_email:" + token
	val, ok := s.store.Take(storeKey)
	if !ok || val == nil {
		return ErrInvalidToken
	}
	payload, ok := val.(string)
	if !ok || payload == "" {
		return ErrInvalidToken
	}

	parts := strings.Split(payload, ":")
	if len(parts) != 3 {
		return ErrInvalidToken
	}
	uidParsed, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || uidParsed > math.MaxUint {
		return ErrInvalidToken
	}
	uid := uint(uidParsed)
	oldEmail := parts[1]
	newEmail := parts[2]

	// Anti-race collision check
	existing, err := s.users.FindByEmail(ctx, newEmail)
	if err != nil {
		return err
	}
	if existing != nil && existing.ID != uid {
		return ErrEmailExists
	}

	user, err := s.users.FindByID(ctx, uid)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.Email = newEmail
	user.IsEmailVerified = true
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	// Invalidate all tokens and sessions
	_ = s.tokens.RevokeAllForUser(ctx, uid)
	if s.sessions != nil {
		_ = s.sessions.RevokeAllForUser(ctx, uid)
	}
	_ = s.bumpPwdVersion(ctx, uid)

	if s.notify != nil {
		_ = s.notify.SendSecurityAlert(ctx, oldEmail, "email_changed", fmt.Sprintf("Your account email was successfully updated to %s. All existing sessions were revoked.", newEmail))
	}

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     newEmail,
			Event:     models.AuditEventEmailChanged,
			IPAddress: ip,
			Success:   true,
			Detail:    "email changed from " + oldEmail,
		})
	}
	return nil
}

// verifySudoOrPassword proves caller identity for sensitive operations (P1.3).
// Returns nil if either:
// 1. sudoToken is a valid TokenTypeSudo JWT for this user.
// 2. password matches the user's current password.
func (s *AuthService) verifySudoOrPassword(ctx context.Context, user *models.User, sudoToken, password string) error {
	if sudoToken != "" && s.jwt != nil {
		claims, err := s.jwt.Verify(sudoToken)
		if err == nil && claims.Type == jwt.TokenTypeSudo && claims.UserID == user.ID && claims.ExpiresAt != nil {
			return nil
		}
	}
	if password != "" && user.Password != "" {
		if hash.CheckPassword(user.Password, password) {
			return nil
		}
		return ErrInvalidCredentials
	}
	return ErrSudoRequired
}

// DeactivateAccount deactivates the caller's account (P1.3).
// Gated by sudo token or password.
// Sets is_active=false, revokes refresh tokens and sessions, bumps pwd_version,
// and denylists the caller's access token jti.
func (s *AuthService) DeactivateAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if err := s.verifySudoOrPassword(ctx, user, sudoToken, password); err != nil {
		return err
	}

	user.IsActive = false
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	// Revoke sessions and tokens
	_ = s.tokens.RevokeAllForUser(ctx, userID)
	if s.sessions != nil {
		_ = s.sessions.RevokeAllForUser(ctx, userID)
	}
	_ = s.bumpPwdVersion(ctx, userID)
	s.denylistAccessToken(accessJTI)

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     user.Email,
			Event:     models.AuditEventAccountDeactivated,
			IPAddress: ip,
			Success:   true,
			Detail:    "account self-deactivated",
		})
	}
	if s.notify != nil {
		_ = s.notify.SendSecurityAlert(ctx, user.Email, "account_deactivated", "Your account has been deactivated. Contact support if you wish to reactivate it.")
	}

	return nil
}

// EraseAccount executes GDPR right-to-erasure for the caller (P1.3).
// Gated by sudo token or password.
// Anonymizes email and username, clears password and full name, deletes
// TOTP rows and recovery codes, unlinks OAuth identities, anonymizes audit email,
// revokes all sessions/tokens, bumps pwd_version, and denylists caller's access token.
func (s *AuthService) EraseAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if err := s.verifySudoOrPassword(ctx, user, sudoToken, password); err != nil {
		return err
	}

	oldEmail := user.Email
	erasedSuffix := uuid.New().String()
	user.Email = fmt.Sprintf("deleted_%s@anonymized.invalid", erasedSuffix)
	user.Username = fmt.Sprintf("deleted_%s", erasedSuffix[:12])
	user.Password = ""
	user.FullName = ""
	user.IsActive = false
	user.IsEmailVerified = false
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	// Purge TOTP device and recovery codes if wired
	if s.totpRepo != nil {
		_ = s.totpRepo.Disable(ctx, userID)
		_ = s.totpRepo.ReplaceRecoveryCodes(ctx, userID, nil)
	}

	// Purge WebAuthn passkeys if wired
	if s.passkeys != nil {
		_ = s.passkeys.RevokeAllForUser(ctx, userID)
	}

	// Purge OAuth identity links if wired
	if s.oauthIdents != nil {
		_ = s.oauthIdents.DeleteAllByUserID(ctx, userID)
	}

	// Anonymize audit logs if supported by the repository
	if s.audits != nil {
		_ = s.audits.AnonymizeUser(ctx, userID)
	}

	// Revoke sessions and tokens
	_ = s.tokens.RevokeAllForUser(ctx, userID)
	if s.sessions != nil {
		_ = s.sessions.RevokeAllForUser(ctx, userID)
	}
	_ = s.bumpPwdVersion(ctx, userID)
	s.denylistAccessToken(accessJTI)

	if s.audits != nil {
		s.audits.Record(ctx, &models.AuditLog{
			UserID:    &user.ID,
			Email:     "anonymized@gdpr.local",
			Event:     models.AuditEventAccountErased,
			IPAddress: ip,
			Success:   true,
			Detail:    "account erased via GDPR right-to-erasure",
		})
	}
	if s.notify != nil {
		_ = s.notify.SendSecurityAlert(ctx, oldEmail, "account_erased", "Your account data has been permanently erased per your request.")
	}

	return nil
}

// ----- 9. Verify email -----

// VerifyEmail accepts a type=verify-email JWT and marks the account verified.
// §1.8 — single-use enforcement via jti (SetNX).
func (s *AuthService) VerifyEmail(ctx context.Context, in EmailVerifyInput) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != jwt.TokenTypeEmailVerify {
		return ErrInvalidToken
	}
	user, err := s.users.FindByID(ctx, claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// §1.8 — single-use enforcement (store + durable backstop, C8).
	if !s.consumeSingleUseToken(ctx, claims.ID, s.jtiStoreTTL(claims)) {
		return ErrInvalidToken
	}
	if err := s.markTokenDurable(ctx, claims.ID, jwt.TokenTypeEmailVerify,
		user.ID, claims.ExpiresAt.Time); err != nil {
		return err
	}

	return s.users.SetEmailVerified(ctx, user, true)
}

// ----- internal helpers -----

// denylist key prefixes + TTL helpers (P0.2). The denylist is store-backed
// (Redis across instances, in-memory per process otherwise). Entries live
// only as long as the tokens they kill — the access TTL / the session's
// remaining lifetime — so the keyspace self-bounds.
const (
	denylistJTIPrefix = "denylist:jti:"
	denylistSIDPrefix = "denylist:sid:"
)

// denylistAccessToken marks one access-token jti revoked for the remaining
// access-token lifetime (bounded by AccessTTL — jti expiry is not carried in
// Logout's inputs, and over-stating the TTL only delays key expiry).
func (s *AuthService) denylistAccessToken(jti string) {
	if s.store == nil || jti == "" {
		return
	}
	s.store.Set(denylistJTIPrefix+jti, "revoked", s.jwtCfg.AccessTTL)
}

// denylistSession marks a session family revoked so every outstanding access
// token carrying its sid dies immediately (P0.3). TTL is the session's
// remaining lifetime so the key disappears with the family it killed.
func (s *AuthService) denylistSession(sess *models.Session) {
	if s.store == nil || sess == nil || sess.ID == "" {
		return
	}
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		ttl = s.jwtCfg.AccessTTL // already expired — keep a minimal grace window
	}
	s.store.Set(denylistSIDPrefix+sess.ID, "revoked", ttl)
}

// issueTokenPair mints a session (unless family reuse is requested), an
// access JWT carrying the session's sid + a unique jti, and an opaque refresh
// token (hash stored) linked to the same session. A non-empty reuseSessionID
// rotates WITHIN an existing family (refresh rotation); empty creates a new
// login session. The access token embeds the user's password version so the
// next credential change kills it (A7).
func (s *AuthService) issueTokenPair(ctx context.Context, user *models.User, ip, ua, reuseSessionID string) (TokenPair, error) {
	sid := reuseSessionID
	if sid == "" && s.sessions != nil {
		sid = uuid.NewString()
		now := time.Now()
		sess := &models.Session{
			ID: sid, UserID: user.ID,
			IPAddress: ip, UserAgent: ua,
			DeviceName:       device.Parse(ua),
			LocationEstimate: s.resolveLocation(ctx, ip),
			LastActiveAt:     now,
			ExpiresAt:        now.Add(s.jwtCfg.RefreshTTL),
		}
		if err := s.sessions.Create(ctx, sess); err != nil {
			return TokenPair{}, err
		}
	} else if sid != "" && s.sessions != nil {
		// Rotation within the family: keep the session row's view current.
		_ = s.sessions.Touch(ctx, sid, ip, ua, device.Parse(ua), s.resolveLocation(ctx, ip), time.Now())
	}
	// P2.1 — the access token carries the user's signed tenant id ("tid").
	// AuthMiddleware promotes it over any client-supplied tenant header, so
	// the effective tenant for authenticated requests is always the one bound
	// at issuance — an X-Tenant-ID spoof cannot cross tenant boundaries.
	access, err := s.jwt.IssueAccessEnterprise(user.ID, user.Role, user.Email,
		s.jwtCfg.AccessTTL, user.PwdVersion, sid, user.TenantID, nil)
	if err != nil {
		return TokenPair{}, err
	}
	refreshPlain, err := hash.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := &models.RefreshToken{
		UserID:           user.ID,
		TokenHash:        hash.HashToken(refreshPlain),
		ExpiresAt:        now.Add(s.jwtCfg.RefreshTTL),
		IPAddress:        ip,
		UserAgent:        ua,
		DeviceName:       device.Parse(ua),
		LocationEstimate: s.resolveLocation(ctx, ip),
		LastActiveAt:     now,
		SessionID:        sid,
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return TokenPair{}, err
	}
	s.maybeNotifyNewIPLogin(ctx, user, ip, ua)
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refreshPlain,
		ExpiresAt:    now.Add(s.jwtCfg.AccessTTL),
	}, nil
}

// resolveLocation maps an IP to a location label, defaulting to "Unknown" when
// no resolver is wired or the lookup fails. Never blocks: the geo resolver is
// expected to honor the request context; a nil resolver is treated as NoOp.
func (s *AuthService) resolveLocation(ctx context.Context, ip string) string {
	if s.geo == nil || ip == "" {
		return geo.UnknownLocation
	}
	if loc := s.geo.Resolve(ctx, ip); loc != "" {
		return loc
	}
	return geo.UnknownLocation
}

// New-IP login notification tuning: the lookback window decides how long an
// IP is considered "known" for a user; the alert timeout bounds the
// background send so a slow relay can never pin a goroutine to a request.
const (
	newIPLookbackWindow = 30 * 24 * time.Hour
	newIPAlertTimeout   = 15 * time.Second
)

// maybeNotifyNewIPLogin sends a TRANSPARENT "new sign-in location" email the
// first time a user logs in from an IP not seen in the lookback window.
// Deliberately NOT risk-based authentication (product decision): no step-up,
// no blocking, no extra prompt — the login flow stays one-shot everywhere,
// and the email is the user-visible audit trail. Fire-and-forget in a
// bounded goroutine: never adds latency to the login response.
func (s *AuthService) maybeNotifyNewIPLogin(ctx context.Context, user *models.User, ip, ua string) {
	_ = ctx // the alert runs on its own background context after this returns
	if s.store == nil || s.notify == nil || ip == "" || !s.cfg.NotifyNewIPLogin {
		return
	}
	key := fmt.Sprintf("knownip:%d:%s", user.ID, ip)
	if !s.store.SetNX(key, "seen", newIPLookbackWindow) {
		return // seen recently — no alert
	}
	deviceName := device.Parse(ua)
	go func() {
		defer func() { _ = recover() }() // a notification must never kill a request goroutine
		// Detached from the request lifecycle (the login response must not
		// wait on SMTP) but carrying its values — trace correlation survives.
		alertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), newIPAlertTimeout)
		defer cancel()
		if err := s.notify.SendNewLoginAlert(alertCtx, user.Email, ip, deviceName); err != nil {
			slog.Warn("login: new-IP notification failed", "user_id", user.ID, "err", err)
		}
	}()
}

// ----- 10. Session & Device Management -----

// ListSessions returns all active (non-expired, non-revoked) sessions for the
// authenticated user, as sanitized SessionInfo projections. currentSID (the
// caller's own session, from the access token's sid claim) marks the
// "this device" row (P1.8). Ordered most-recently-active first by the
// repository. With no session repo wired (legacy mode) it falls back to the
// refresh-token rows and marks none as current.
func (s *AuthService) ListSessions(ctx context.Context, userID uint, currentSID string) ([]SessionInfo, error) {
	if s.sessions != nil {
		rows, err := s.sessions.FindActiveByUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("list sessions: %w", err)
		}
		out := make([]SessionInfo, 0, len(rows))
		for i := range rows {
			sess := &rows[i]
			out = append(out, SessionInfo{
				ID:               sess.ID,
				IPAddress:        sess.IPAddress,
				UserAgent:        sess.UserAgent,
				DeviceName:       sess.DeviceName,
				LocationEstimate: sess.LocationEstimate,
				CreatedAt:        sess.CreatedAt,
				LastActiveAt:     sess.LastActiveAt,
				ExpiresAt:        sess.ExpiresAt,
				IsCurrent:        sess.ID == currentSID,
			})
		}
		return out, nil
	}
	// Legacy fallback: refresh-token rows as sessions (P0.3 pre-migration).
	rows, err := s.tokens.FindActiveByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]SessionInfo, 0, len(rows))
	for i := range rows {
		rt := &rows[i]
		out = append(out, SessionInfo{
			ID:               strconv.FormatUint(uint64(rt.ID), 10),
			IPAddress:        rt.IPAddress,
			UserAgent:        rt.UserAgent,
			DeviceName:       rt.DeviceName,
			LocationEstimate: rt.LocationEstimate,
			CreatedAt:        rt.CreatedAt,
			LastActiveAt:     rt.LastActiveAt,
			ExpiresAt:        rt.ExpiresAt,
		})
	}
	return out, nil
}

// RevokeSession revokes a single session (device) by its UUID, scoped to the
// caller's userID so one user cannot revoke another user's session (IDOR
// defense). The whole family dies together: the session row, its
// refresh-token chain, and — via the sid denylist — its outstanding ACCESS
// tokens (P0.2/P0.3).
func (s *AuthService) RevokeSession(ctx context.Context, sessionID string, userID uint, ip string) error {
	if s.sessions == nil {
		// Legacy fallback: refresh-token rows as sessions (P0.3 pre-migration).
		id, err := strconv.ParseUint(sessionID, 10, 64)
		if err != nil || id > math.MaxUint {
			return ErrSessionNotFound
		}
		if err := s.tokens.RevokeByID(ctx, uint(id), userID); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrSessionNotFound
			}
			return fmt.Errorf("revoke session: %w", err)
		}
		uid := userID
		s.audits.Record(ctx, &models.AuditLog{
			UserID: &uid, Event: models.AuditEventSessionRevoked,
			IPAddress: ip, Success: true,
		})
		return nil
	}
	sess, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if sess == nil || sess.UserID != userID {
		return ErrSessionNotFound
	}
	if err := s.sessions.RevokeByID(ctx, sessionID, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("revoke session: %w", err)
	}
	if err := s.tokens.RevokeBySession(ctx, sessionID); err != nil {
		return fmt.Errorf("revoke session: revoke family tokens: %w", err)
	}
	s.denylistSession(sess)
	uid := userID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: models.AuditEventSessionRevoked,
		IPAddress: ip, Success: true,
	})
	return nil
}

// isLocked reports whether the account is currently in a temporary lockout.
func (s *AuthService) isLocked(user *models.User) bool {
	return user.LockedUntil != nil && time.Now().Before(*user.LockedUntil)
}

// recordFailedLogin increments the counter and triggers a lockout when the
// threshold is reached. §3 — exponential backoff: repeat offenders get
// progressively longer lockouts via MaxLockoutMultiplier, tracked in the store.
// When MaxLockoutMultiplier <= 0 (unset/disabled), the plain base duration is
// used with no scaling.
func (s *AuthService) recordFailedLogin(ctx context.Context, user *models.User, email, ip string) {
	var lockUntil *time.Time
	if user.FailedLoginAttempts+1 >= s.cfg.MaxLoginAttempts {
		duration := s.cfg.LoginLockoutDuration
		if s.store != nil && s.cfg.MaxLockoutMultiplier > 0 {
			// Count how many lockouts this user has had in the last 24h.
			lockoutKey := fmt.Sprintf("lockouts:%d", user.ID)
			lockoutCount := s.store.IncrBy(lockoutKey, 1, 24*time.Hour)
			// Scale: base × min(count, MaxLockoutMultiplier). First lockout
			// (count=1) → base; second → 2×base; etc., capped.
			mult := lockoutCount
			if int(mult) > s.cfg.MaxLockoutMultiplier {
				mult = int64(s.cfg.MaxLockoutMultiplier)
			}
			if mult < 1 {
				mult = 1
			}
			duration = time.Duration(int64(s.cfg.LoginLockoutDuration) * mult)
		}
		t := time.Now().Add(duration)
		lockUntil = &t
	}
	if err := s.users.IncrementFailedAttempts(ctx, user, lockUntil); err != nil {
		// Log the error — lockout enforcement depends on this write succeeding.
		// Do NOT return the error to the caller (login should still fail with
		// ErrInvalidCredentials, not a 500), but the failure must be observable.
		slog.Error("recordFailedLogin: increment failed attempts",
			"user_id", user.ID, "err", err)
	}
	s.recordLoginFailIP(ctx, ip)
	s.recordLoginFailAccount(email)
	s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "bad password"))
}

// recordLoginFailAccount grows the per-account login velocity counter — its
// only writer (C9: failures only; a successful login deletes the key instead).
func (s *AuthService) recordLoginFailAccount(email string) {
	if s.store != nil && email != "" {
		s.store.IncrBy("login:acct:"+email, 1, s.rlCfg.LoginWindow)
	}
}

// recordLoginFailIP increments the per-IP failure counter used by the adaptive
// CAPTCHA gate (§3). Tracked in the store with a 1-hour window. IPv6 sources
// are collapsed to their /64 prefix so address rotation inside one subnet
// cannot bypass the gate (or flood the store with distinct keys).
func (s *AuthService) recordLoginFailIP(ctx context.Context, ip string) {
	if s.store != nil && ip != "" {
		_ = s.store.IncrBy(ipCounterKey("loginfail:", ip), 1, time.Hour)
	}
}

// pwdVerCacheTTL bounds how long AuthMiddleware sees a stale password
// version after a credential change (A7). 60s keeps the per-request cost at
// one store hit; the exposure window for a revoked-but-still-accepted access
// token is this TTL, and at most AccessTTL when the store is unavailable.
const pwdVerCacheTTL = 60 * time.Second

// bumpPwdVersion advances the credential counter and drops its cached value
// so AuthMiddleware sees the new version immediately instead of after the
// cache TTL (A7).
func (s *AuthService) bumpPwdVersion(ctx context.Context, userID uint) error {
	if err := s.users.BumpPwdVersion(ctx, userID); err != nil {
		return err
	}
	if s.store != nil {
		s.store.Delete(fmt.Sprintf("pwdver:%d", userID))
	}
	return nil
}

// CurrentPwdVersion returns the user's live credential version for
// AuthMiddleware (A7): store-cached for pwdVerCacheTTL, DB on cache miss.
// A store failure falls through to the DB; when both fail the error is
// returned and callers must decide (the middleware then fails OPEN — the
// remaining bound is AccessTTL, the documented worst case).
func (s *AuthService) CurrentPwdVersion(ctx context.Context, userID uint) (int64, error) {
	key := fmt.Sprintf("pwdver:%d", userID)
	if s.store != nil {
		if v, ok := s.store.Get(key); ok {
			switch n := v.(type) {
			case int64:
				return n, nil
			case int:
				return int64(n), nil
			case string:
				if parsed, err := strconv.ParseInt(n, 10, 64); err == nil {
					return parsed, nil
				}
			}
		}
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return 0, err
	}
	if user == nil {
		return 0, nil
	}
	if s.store != nil {
		s.store.Set(key, user.PwdVersion, pwdVerCacheTTL)
	}
	return user.PwdVersion, nil
}

// markTokenUsed uses SetNX on the store to atomically check-and-mark a JWT
// jti as consumed. Returns false if already used (single-use enforcement §1.8).
// The TTL derives from the token's own expiry — a hardcoded value shorter than
// a configured token TTL would let a consumed token revive after the store
// key lapses while the token is still cryptographically valid.
func (s *AuthService) markTokenUsed(jti string, ttl time.Duration) bool {
	if s.store == nil {
		return true // store disabled (tests) — allow through
	}
	key := "jti:" + jti
	return s.store.SetNX(key, "used", ttl)
}

// jtiStoreTTL sizes the volatile single-use window from the token's own
// expiry plus a safety margin (clock skew between replicas, purge cadence).
func (s *AuthService) jtiStoreTTL(claims *jwt.Claims) time.Duration {
	ttl := 24 * time.Hour // conservative default when no expiry is present
	if claims != nil && claims.ExpiresAt != nil {
		if until := time.Until(claims.ExpiresAt.Time); until > 0 {
			ttl = until + time.Hour
		}
	}
	return ttl
}

// markTokenDurable persists the jti to the used_tokens table. The error is
// PROPAGATED, never swallowed: the durable table is the C8 backstop against a
// store flush reviving consumed tokens, so a silent failure is exactly the
// replay window it exists to close. The caller fails the flow — the volatile
// jti key is already set, so the user requests a fresh token; replay stays
// impossible either way.
func (s *AuthService) markTokenDurable(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) error {
	if s.usedTokens == nil {
		return nil // no durable guard wired (tests) — store decision stands
	}
	if _, err := s.usedTokens.MarkUsed(ctx, jti, tokenType, userID, exp); err != nil {
		return fmt.Errorf("single-use backstop: %w", err)
	}
	return nil
}

// consumeSingleUseToken enforces one-time use of a jti across BOTH guards:
// the volatile store (fast, shared) and the durable used_tokens table. A
// store MISS is not proof of freshness — a Redis flush/eviction would revive
// consumed tokens — so the DB replay check runs on every miss and fails
// CLOSED (a token whose history cannot be verified is rejected, C8). With no
// store wired at all, the durable table alone decides.
func (s *AuthService) consumeSingleUseToken(ctx context.Context, jti string, ttl time.Duration) bool {
	if !s.markTokenUsed(jti, ttl) {
		return false
	}
	if s.usedTokens == nil {
		return true // no durable guard wired (tests) — store decision stands
	}
	used, err := s.usedTokens.IsUsed(ctx, jti)
	if err != nil {
		return false // cannot prove freshness — fail closed
	}
	return !used
}

// ipCounterKey builds a per-IP counter key, collapsing IPv6 sources to their
// /64 prefix. Unauthenticated endpoints mint attacker-keyed state; without
// the collapse, one host cycling addresses inside its /64 makes the store
// accumulate millions of hour-TTL keys (evicting jti/replay guards or OOMing
// the in-memory store). The masking lives in netutil.CanonicalIP so the
// middleware limiter keys on the exact same form (V4 parity).
func ipCounterKey(prefix, ip string) string {
	return prefix + netutil.CanonicalIP(ip)
}

// validatePassword enforces complexity, dictionary checks against username/email,
// and optional zxcvbn password scoring (P1.7).
func validatePassword(pw string, minScore int, userInputs ...string) error {
	if len(pw) < 8 {
		return ErrPasswordTooWeak
	}
	// §5 — password length cap before bcrypt.
	if len(pw) > hash.MaxPasswordBytes {
		return ErrPasswordTooWeak
	}
	var hasLetter, hasNumber bool
	for _, r := range pw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		case r >= '0' && r <= '9':
			hasNumber = true
		}
	}
	if !hasLetter || !hasNumber {
		return ErrPasswordTooWeak
	}

	// Reject if password contains username or local-part of email (case-insensitive)
	pwLower := strings.ToLower(pw)
	var sanitizedInputs []string
	for _, input := range userInputs {
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "" {
			continue
		}
		sanitizedInputs = append(sanitizedInputs, input)
		if len(input) >= 3 && strings.Contains(pwLower, input) {
			return ErrPasswordTooWeak
		}
	}

	if minScore > 0 {
		score := zxcvbn.PasswordStrength(pw, sanitizedInputs).Score
		if score < minScore {
			return ErrPasswordTooWeak
		}
	}

	return nil
}

// mapDuplicateKey inspects a DB error from user.Create and maps MySQL 1062
// (duplicate key) to ErrEmailExists or ErrUsernameExists (§1.7).
func mapDuplicateKey(email, username string, err error) error {
	// Check if the raw error (or its cause) is a MySQL duplicate key.
	if isMySQLDup(err) {
		// Best-effort guess based on which field the email/username might be
		// duplicating — both indexes are unique. Try to identify from the error
		// message substring.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "email"):
			return ErrEmailExists
		case strings.Contains(msg, "username"):
			return ErrUsernameExists
		default:
			// Can't tell which — try a targeted lookup.
			return ErrEmailExists // more likely in practice
		}
	}
	return fmt.Errorf("register: create user: %w", err)
}

// isMySQLDup inspects a DB error for MySQL duplicate-key (1062). §1.7 explicitly
// requires errors.As to *mysql.MySQLError — not fragile string matching.
func isMySQLDup(err error) bool {
	var myErr *mysql.MySQLError
	return errors.As(err, &myErr) && myErr.Number == 1062
}

func loginFailedEvent(uid *uint, email, ip, detail string) *models.AuditLog {
	return &models.AuditLog{
		UserID: uid, Email: email, Event: models.AuditEventLoginFailed,
		IPAddress: ip, Success: false, Detail: detail,
	}
}

// IssuePasskeyTokenPair issues the standard access+refresh pair for a user
// who completed a WebAuthn authentication ceremony (W5). The ceremony has
// already proven possession of a registered credential; this is the same
// issuance path a password login uses — including the SAME account-state
// gate: a disabled account can never mint sessions here, exactly like it
// cannot via password, OAuth, or refresh.
func (s *AuthService) IssuePasskeyTokenPair(ctx context.Context, user *models.User, ip, ua string) (TokenPair, UserProfile, error) {
	if !user.IsActive {
		return TokenPair{}, UserProfile{}, ErrAccountDisabled
	}
	pair, err := s.issueTokenPair(ctx, user, ip, ua, "")
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	return pair, FromUser(user), nil
}
