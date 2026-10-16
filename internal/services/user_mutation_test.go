package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// The only test seam pauses AFTER the real repository read. Every mutation,
// session check, login and persistence operation uses the production adapters.
type interleavedUsers struct {
	*repositories.UserRepository
	afterRead func()
}

func (r *interleavedUsers) FindByID(ctx context.Context, id uint) (*models.User, error) {
	u, err := r.UserRepository.FindByID(ctx, id)
	if err == nil && u != nil && r.afterRead != nil {
		f := r.afterRead
		r.afterRead = nil
		f()
	}
	return u, err
}

func mutationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	mutationMust(t, err)
	conn, err := db.DB()
	mutationMust(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { mutationMust(t, conn.Close()) })
	mutationMust(t, db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.Session{}, &models.AccessRevocation{}, &models.Tenant{}, &models.AuditLog{}, &models.UsedToken{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}))
	return db
}

func mutationMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestF02StaleUserMutations(t *testing.T) {
	s := store.NewInMemoryStore(0)
	t.Cleanup(s.Close)
	runStaleUserMutations(t, mutationDB(t), s)
}

func runStaleUserMutations(t *testing.T, db *gorm.DB, kv interface {
	store.Store
	identity.SecurityStore
}) {
	t.Helper()
	for _, tid := range []string{"default", "repair-tenant"} {
		tr := models.Tenant{ID: tid, Slug: tid, Name: tid, IsActive: true}
		mutationMust(t, db.Where("id = ?", tid).FirstOrCreate(&tr).Error)
		ctx := tenant.WithTenant(context.Background(), tid)
		for _, transition := range []string{"suspend", "grant", "credential", "inactive", "lockout"} {
			for _, operation := range []string{"profile", "email"} {
				t.Run(tid+"/"+transition+"/"+operation, func(t *testing.T) {
					users := repositories.NewUserRepository(db)
					tokens := repositories.NewRefreshTokenRepository(db)
					sessions := repositories.NewSessionRepository(db)
					rbac := repositories.NewRBACRepository(db)
					key := sha256.Sum256([]byte("F02 repair public synthetic key"))
					m, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: "HS256", CurrentID: "repair", CurrentSecret: base64.StdEncoding.EncodeToString(key[:])})
					mutationMust(t, err)
					a := &identity.Authority{DB: db, Store: kv}
					wrapped := &interleavedUsers{UserRepository: users}
					svc := NewAuthService(wrapped, tokens, repositories.NewUsedTokenRepository(db), repositories.NewAuditRepository(db), kv, m, config.AuthConfig{BcryptCost: hash.MinCost}, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: time.Minute, RefreshTTL: time.Hour}, &mockNotifier{}, nil, nil, nil, nil, WithSessionRepo(sessions), WithAuthPermissions(rbac), WithAccessRevoker(a), WithAccessState(func(ctx context.Context, c *jwt.Claims) error {
						if err := a.Check(ctx, c); errors.Is(err, identity.ErrInactive) {
							return ErrInvalidCredentials
						} else {
							return err
						}
					}))
					password := "SyntheticPassword42!"
					hashed, err := hash.HashPassword(password, hash.MinCost)
					mutationMust(t, err)
					id := uuid.NewString()
					u := &models.User{Username: id, Email: id + "@example.invalid", Password: hashed, FullName: "Old", IsActive: true, IsEmailVerified: true}
					mutationMust(t, users.Create(ctx, u))
					pair, _, err := svc.IssuePasskeyTokenPair(ctx, u, "127.0.0.1", "synthetic")
					mutationMust(t, err)
					claims, err := m.VerifyAccessV1(pair.AccessToken, jwt.FinnAudience)
					mutationMust(t, err)
					mutationMust(t, a.Check(ctx, claims))
					var authoritative *models.User
					interleave := func() {
						switch transition {
						case "suspend":
							mutationMust(t, a.Suspend(ctx, u.ID))
						case "grant":
							role := &models.Role{TenantID: tid, Name: "repair-" + id}
							mutationMust(t, db.Create(role).Error)
							permission := &models.Permission{Name: "repair:" + id}
							mutationMust(t, db.Create(permission).Error)
							mutationMust(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error)
							mutationMust(t, rbac.AssignRoleToUser(ctx, u.ID, role.ID))
						case "credential":
							password = "ChangedSynthetic42!"
							h, err := hash.HashPassword(password, hash.MinCost)
							mutationMust(t, err)
							mutationMust(t, users.CredentialChangeTx(ctx, u.ID, h, func(tx *gorm.DB) error { return sessions.RevokeAllForUserTx(tx, u.ID) }))
						case "inactive":
							mutationMust(t, db.Model(&models.User{}).Where("id = ?", u.ID).Update("is_active", false).Error)
						case "lockout":
							until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
							mutationMust(t, users.IncrementFailedAttempts(ctx, u, &until))
						}
						var err error
						authoritative, err = users.FindByID(ctx, u.ID)
						mutationMust(t, err)
					}
					newEmail := "changed-" + u.Email
					if operation == "email" {
						token := uuid.NewString()
						kv.Set("change_email:"+token, fmt.Sprintf("%d:%s:%s", u.ID, u.Email, newEmail), time.Minute)
						wrapped.afterRead = interleave
						mutationMust(t, svc.ConfirmChangeEmail(ctx, token, "127.0.0.1"))
					} else {
						stale, err := users.FindByID(ctx, u.ID)
						mutationMust(t, err)
						interleave()
						stale.FullName = "" // an intentional zero value must persist.
						mutationMust(t, users.Update(ctx, stale))
					}
					got, err := users.FindByID(ctx, u.ID)
					mutationMust(t, err)
					if got.AdminSuspended != authoritative.AdminSuspended || got.AuthEpoch != authoritative.AuthEpoch || got.PwdVersion < authoritative.PwdVersion || got.Password != authoritative.Password || got.IsActive != authoritative.IsActive || got.FailedLoginAttempts != authoritative.FailedLoginAttempts || !sameMutationTime(got.LockedUntil, authoritative.LockedUntil) {
						t.Fatalf("stale %s overwrote %s: suspended=%v epoch=%d pwdver=%d active=%v attempts=%d", operation, transition, got.AdminSuspended, got.AuthEpoch, got.PwdVersion, got.IsActive, got.FailedLoginAttempts)
					}
					if operation == "email" && (got.Email != newEmail || !got.IsEmailVerified) || operation == "profile" && got.FullName != "" {
						t.Fatal("legitimate mutation lost")
					}
					if transition != "lockout" || operation == "email" {
						if err := a.Check(ctx, claims); !errors.Is(err, identity.ErrInactive) {
							t.Fatalf("old credential active: %v", err)
						}
					}
					loginPair, _, _, err := svc.Login(ctx, LoginInput{Email: got.Email, Password: password}, "127.0.0.1", "synthetic")
					switch transition {
					case "suspend", "inactive":
						if !errors.Is(err, ErrAccountDisabled) || loginPair.AccessToken != "" {
							t.Fatalf("disabled account login: %v", err)
						}
					case "lockout":
						if !errors.Is(err, ErrAccountLocked) {
							t.Fatalf("locked account login: %v", err)
						}
					case "grant", "credential":
						mutationMust(t, err)
						fresh, err := m.VerifyAccessV1(loginPair.AccessToken, jwt.FinnAudience)
						mutationMust(t, err)
						mutationMust(t, a.Check(ctx, fresh))
						if fresh.AuthEpoch != got.AuthEpoch || fresh.PwdVer != got.PwdVersion {
							t.Fatal("fresh login issued stale versions")
						}
					}
				})
			}
		}
	}
}

func sameMutationTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func TestF02MutationOwnership(t *testing.T) {
	db := mutationDB(t)
	runMutationOwnership(t, db)
	runMutationAdapterFailure(t, db)
}

func runMutationAdapterFailure(t *testing.T, db *gorm.DB) {
	t.Helper()
	conn, err := db.DB()
	mutationMust(t, err)
	mutationMust(t, conn.Close())
	u := &models.User{ID: 1, TenantID: "default"}
	r := repositories.NewUserRepository(db)
	for name, mutate := range map[string]func() error{
		"profile":    func() error { return r.Update(context.Background(), u) },
		"email":      func() error { return r.UpdateEmail(context.Background(), u) },
		"deactivate": func() error { return r.Deactivate(context.Background(), u.ID) },
		"erase":      func() error { return r.Erase(context.Background(), u) },
	} {
		t.Run(name+" actual adapter outage", func(t *testing.T) {
			if err := mutate(); err == nil || errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("database outage became absence/success: %v", err)
			}
		})
	}
}

func runMutationOwnership(t *testing.T, db *gorm.DB) {
	t.Helper()
	tid := "ownership-" + uuid.NewString()[:8]
	ctx := tenant.WithTenant(context.Background(), tid)
	mutationMust(t, db.Create(&models.Tenant{ID: tid, Slug: tid, Name: tid, IsActive: true}).Error)
	users := repositories.NewUserRepository(db)
	u := &models.User{Username: uuid.NewString(), Email: uuid.NewString() + "@example.invalid", Password: "new-authoritative-hash", FullName: "Name", IsEmailVerified: true, IsActive: true, AdminSuspended: true, PwdVersion: 8, AuthEpoch: 9, FailedLoginAttempts: 3}
	mutationMust(t, users.Create(ctx, u))
	stale := *u
	stale.AdminSuspended, stale.PwdVersion, stale.AuthEpoch = false, 0, 0
	stale.Password, stale.FullName, stale.FailedLoginAttempts = "stale", "", 0
	stale.IsActive, stale.IsEmailVerified = false, false
	mutations := map[string]func(context.Context, *models.User) error{
		"profile": users.Update, "email": users.UpdateEmail,
		"deactivate": func(ctx context.Context, u *models.User) error { return users.Deactivate(ctx, u.ID) },
		"erase":      users.Erase,
	}
	for name, mutate := range mutations {
		t.Run(name+" tenant and affected rows", func(t *testing.T) {
			for _, foreign := range []string{"default", "foreign"} {
				foreignCtx := tenant.WithTenant(context.Background(), foreign)
				if err := mutate(foreignCtx, &stale); !errors.Is(err, gorm.ErrRecordNotFound) {
					t.Fatalf("foreign mutation %s: %v", foreign, err)
				}
				// Neither a supplied matching tenant nor an omitted model tenant may
				// change the context's authority or turn a miss into an upsert.
				forged := stale
				forged.TenantID = foreign
				if err := mutate(foreignCtx, &forged); !errors.Is(err, gorm.ErrRecordNotFound) {
					t.Fatalf("forged model tenant: %v", err)
				}
				forged.TenantID = ""
				if err := mutate(foreignCtx, &forged); !errors.Is(err, gorm.ErrRecordNotFound) {
					t.Fatalf("empty model tenant: %v", err)
				}
			}
			missing := stale
			missing.ID = 999999999
			if err := mutate(ctx, &missing); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("missing update upserted/succeeded: %v", err)
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if err := mutate(cancelled, &stale); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled write succeeded: %v", err)
			}
		})
	}
	mutationMust(t, users.Update(ctx, &stale))
	mutationMust(t, users.UpdateEmail(ctx, &stale))
	got, err := users.FindByID(ctx, u.ID)
	mutationMust(t, err)
	if !got.AdminSuspended || !got.IsActive || got.AuthEpoch != 9 || got.PwdVersion != 8 || got.Password != u.Password || got.FailedLoginAttempts != 3 || got.IsEmailVerified || got.FullName != "" {
		t.Fatal("profile/email mutation ownership or zero-value persistence failed")
	}
	// Freeze updated_at to exercise MySQL's zero-changed-row idempotence path.
	fixed := db.Session(&gorm.Session{NowFunc: func() time.Time { return u.UpdatedAt }})
	for i := 0; i < 2; i++ {
		mutationMust(t, repositories.NewUserRepository(fixed).UpdateEmail(ctx, &stale))
	}
	mutationMust(t, users.Deactivate(ctx, u.ID))
	mutationMust(t, users.Erase(ctx, &stale))
	got, err = users.FindByID(ctx, u.ID)
	mutationMust(t, err)
	if got.IsActive || got.IsEmailVerified || got.Password != "" || got.FullName != "" || !got.AdminSuspended || got.PwdVersion != 8 || got.AuthEpoch != 9 || got.FailedLoginAttempts != 3 {
		t.Fatal("deactivation/erasure disabled or stale security state restored")
	}

	for _, operation := range []string{"deactivate", "erase"} {
		t.Run(operation+" service interleaving", func(t *testing.T) {
			kv := store.NewInMemoryStore(0)
			t.Cleanup(kv.Close)
			wrapped := &interleavedUsers{UserRepository: users}
			m := jwt.NewJWTManager("public synthetic legacy ceremony key", "finnapigo")
			svc := NewAuthService(wrapped, repositories.NewRefreshTokenRepository(db), repositories.NewUsedTokenRepository(db), repositories.NewAuditRepository(db), kv, m, config.AuthConfig{}, config.RateLimitConfig{}, config.JWTConfig{}, &mockNotifier{}, nil, nil, nil, nil, WithSessionRepo(repositories.NewSessionRepository(db)))
			victim := &models.User{Username: uuid.NewString(), Email: uuid.NewString() + "@example.invalid", Password: "hash", IsActive: true, IsEmailVerified: true, FullName: "Name"}
			mutationMust(t, users.Create(ctx, victim))
			wrapped.afterRead = func() { mutationMust(t, (&identity.Authority{DB: db}).Suspend(ctx, victim.ID)) }
			sudo, err := m.Issue(victim.ID, "user", victim.Email, jwt.TokenTypeSudo, time.Minute)
			mutationMust(t, err)
			if operation == "deactivate" {
				mutationMust(t, svc.DeactivateAccount(ctx, victim.ID, sudo, "", "", "127.0.0.1"))
			} else {
				mutationMust(t, svc.EraseAccount(ctx, victim.ID, sudo, "", "", "127.0.0.1"))
			}
			reloaded, err := users.FindByID(ctx, victim.ID)
			mutationMust(t, err)
			if !reloaded.AdminSuspended || reloaded.IsActive || reloaded.AuthEpoch != 1 || reloaded.PwdVersion != 2 {
				t.Fatal("service restored stale security state")
			}
			if operation == "erase" && (reloaded.Password != "" || reloaded.FullName != "" || reloaded.IsEmailVerified || reloaded.Email == victim.Email || reloaded.Username == victim.Username) {
				t.Fatal("service erasure failed")
			}
		})
	}
}
