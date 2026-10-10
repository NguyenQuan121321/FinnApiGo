package tenantboundary_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestF01LocalMatrix(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Session{}, &models.RefreshToken{}, &models.AuditLog{}, &models.PasskeyCredential{}, &models.TrustedDevice{}, &models.OAuthIdentity{}, &models.TOTPDevice{}, &models.RecoveryCode{}, &models.Role{}, &models.Permission{}, &models.UserRole{}, &models.RolePermission{}); err != nil {
		t.Fatal(err)
	}
	runF01Matrix(t, db)
}

// The identical matrix runs against migrated MySQL with the integration tag.
// SQLite provides quick regression feedback, never MySQL acceptance evidence.
func runF01Matrix(t *testing.T, db *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	users := repositories.NewUserRepository(db)
	sessions := repositories.NewSessionRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	audits := repositories.NewAuditRepository(db)
	passkeys := repositories.NewPasskeyRepository(db)
	devices := repositories.NewTrustedDeviceRepository(db)
	oauth := repositories.NewOAuthIdentityRepository(db)
	totp := repositories.NewTOTPRepository(db)
	rbac := repositories.NewRBACRepository(db)
	mgr := jwt.NewJWTManager("synthetic-f01-signing-fixture-key", "f01-tests")
	cache := store.NewInMemoryStore(0)
	admin := services.NewAdminService(users, sessions, tokens, audits, cache)
	auth := services.NewAuthService(users, tokens, nil, audits, cache, mgr, config.AuthConfig{}, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: time.Minute, RefreshTTL: time.Hour}, nil, nil, nil, nil, nil, services.WithSessionRepo(sessions), services.WithAuthPermissions(rbac), services.WithBcryptCost(4))
	router := routes.Register(routes.Deps{JWT: mgr, Auth: handlers.NewAuthHandler(auth, nil), MFA: handlers.NewMFAHandler(nil, mgr, time.Minute), Sessions: handlers.NewSessionHandler(auth), Admin: handlers.NewAdminHandler(admin), PwdVersion: auth.CurrentPwdVersion, RateLimit: middleware.NewRateLimiter(10000, 10000, time.Minute), RBACChecker: rbac})

	tenants := []string{"A", "B", "default"}
	actors := map[string]*models.User{}
	targets := map[string]*models.User{}
	for _, tid := range tenants {
		ctx := tenant.WithTenant(context.Background(), tid)
		for _, name := range []string{"actor", "target"} {
			u := &models.User{Username: name, Email: name + "@example.com", Password: "hash", FullName: "canary-" + tid, Role: "admin"}
			if err := users.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			if name == "actor" {
				actors[tid] = u
			} else {
				targets[tid] = u
			}
		}
		u := targets[tid]
		if err := sessions.Create(ctx, &models.Session{ID: "session-" + tid, UserID: u.ID, DeviceName: "canary-" + tid, LastActiveAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := tokens.Create(ctx, &models.RefreshToken{UserID: u.ID, TokenHash: "hash-" + tid, SessionID: "session-" + tid, LastActiveAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := passkeys.Create(ctx, &models.PasskeyCredential{UserID: u.ID, CredentialID: []byte("credential-" + tid), PublicKey: []byte("public"), Transports: "[]"}); err != nil {
			t.Fatal(err)
		}
		if err := devices.Create(ctx, &models.TrustedDevice{UserID: u.ID, DeviceHash: "device-" + tid, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := oauth.Create(ctx, &models.OAuthIdentity{UserID: u.ID, Provider: "google", ProviderUserID: "subject-" + tid}); err != nil {
			t.Fatal(err)
		}
		if err := totp.Upsert(ctx, &models.TOTPDevice{UserID: u.ID, Secret: "fixture", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		audits.Record(ctx, &models.AuditLog{UserID: &u.ID, Event: "fixture", Detail: "canary-" + tid})
	}
	issue := func(t *testing.T, tid, role string, perms []string) string {
		t.Helper()
		tok, err := mgr.IssueAccessEnterprise(actors[tid].ID, role, actors[tid].Email, time.Minute, 0, "actor-session-"+tid, tid, perms)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	request := func(method, path, token, spoof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"durationSeconds":3600}`))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("X-Tenant-ID", spoof)
		req.Header.Set("X-Tenant-Slug", spoof)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	fullPerms := []string{"users:read", "users:write", "sessions:read", "audit:export"}
	for _, name := range fullPerms {
		if err := db.Where("name = ?", name).FirstOrCreate(&models.Permission{Name: name}).Error; err != nil {
			t.Fatal(err)
		}
	}
	roles := map[string]*models.Role{}
	for _, tid := range tenants {
		ctx := tenant.WithTenant(context.Background(), tid)
		role := &models.Role{Name: "f01-admin-grants"}
		if err := rbac.CreateRole(ctx, role, fullPerms); err != nil {
			t.Fatal(err)
		}
		roles[tid] = role
		if err := rbac.AssignRoleToUser(ctx, actors[tid].ID, role.ID); err != nil {
			t.Fatal(err)
		}
		pair, _, err := auth.IssuePasskeyTokenPair(ctx, actors[tid], "127.0.0.1", "f01-test")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := mgr.Verify(pair.AccessToken)
		if err != nil || claims.TenantID != tid || len(claims.Permissions) != len(fullPerms) {
			t.Fatalf("issued grants/tenant: %v %v", claims, err)
		}
	}
	for _, tid := range tenants {
		t.Run(tid, func(t *testing.T) {
			ctx := tenant.WithTenant(context.Background(), tid)
			// role=user with explicit grants is authorized; admin alone is not.
			full := issue(t, tid, "user", fullPerms)
			adminFull := issue(t, tid, "admin", fullPerms)
			writer := issue(t, tid, "admin", []string{"users:write"})
			for _, targetTenant := range tenants {
				u := targets[targetTenant]
				if targetTenant == tid {
					continue
				}
				t.Run("deny-"+targetTenant, func(t *testing.T) {
					var before models.User
					if err := db.First(&before, u.ID).Error; err != nil {
						t.Fatal(err)
					}
					if got, err := users.FindByID(ctx, u.ID); err != nil || got != nil {
						t.Fatalf("foreign user disclosed: %v %v", got, err)
					}
					for _, op := range []string{"lock", "unlock", "force-logout"} {
						path := fmt.Sprintf("/api/v1/admin/users/%d/%s", u.ID, op)
						for _, credential := range []string{full, adminFull, writer} {
							w := request(http.MethodPost, path, credential, targetTenant)
							missing := request(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/999999/%s", op), credential, targetTenant)
							if w.Code != 404 || w.Body.String() != missing.Body.String() {
								t.Fatalf("%s hidden-record semantics: %d %s", op, w.Code, w.Body.String())
							}
						}
					}
					copyUser := *u
					copyUser.TenantID = tid
					copyUser.FullName = "changed"
					mutations := []func() error{
						func() error { return users.Update(ctx, &copyUser) },
						func() error { return users.UpdatePassword(ctx, &copyUser, "changed") },
						func() error { return users.SetLock(ctx, u.ID, nil) },
						func() error { return users.BumpPwdVersion(ctx, u.ID) },
						func() error { return users.SetEmailVerified(ctx, &copyUser, true) },
						func() error { return sessions.RevokeByID(ctx, "session-"+targetTenant, u.ID) },
						func() error { return sessions.Touch(ctx, "session-"+targetTenant, "", "", "changed", "", time.Now()) },
						func() error { return sessions.RevokeAllForUser(ctx, u.ID) },
						func() error { return tokens.RevokeAllForUser(ctx, u.ID) },
						func() error { return totp.Upsert(ctx, &models.TOTPDevice{UserID: u.ID}) },
						func() error { return totp.ReplaceRecoveryCodes(ctx, u.ID, nil) },
					}
					for i, mutate := range mutations {
						if err := mutate(); !errors.Is(err, gorm.ErrRecordNotFound) {
							t.Fatalf("foreign mutation %d: %v", i, err)
						}
					}
					called := false
					if err := users.CredentialChangeTx(ctx, u.ID, "changed", func(tx *gorm.DB) error { called = true; return nil }); !errors.Is(err, gorm.ErrRecordNotFound) || called {
						t.Fatalf("foreign credential transaction: %v callback=%v", err, called)
					}
					if ok, err := users.SetFirstPassword(ctx, u.ID, "changed"); err != nil || ok {
						t.Fatalf("foreign conditional password: %v %v", ok, err)
					}
					if _, _, err := users.ListPaginated(ctx, targetTenant, 1, 20, ""); !errors.Is(err, gorm.ErrRecordNotFound) {
						t.Fatalf("tenant argument override: %v", err)
					}
					if _, err := sessions.FindAllActiveByTenant(ctx, targetTenant); !errors.Is(err, gorm.ErrRecordNotFound) {
						t.Fatal("foreign session list")
					}
					if _, err := audits.StreamAll(ctx, targetTenant); !errors.Is(err, gorm.ErrRecordNotFound) {
						t.Fatal("foreign export")
					}
					if err := rbac.AssignRoleToUser(ctx, actors[tid].ID, roles[targetTenant].ID); !errors.Is(err, gorm.ErrRecordNotFound) {
						t.Fatal("foreign role assigned")
					}
					if grants, err := rbac.GetUserPermissions(ctx, actors[targetTenant].ID); err != nil || len(grants) != 0 {
						t.Fatal("foreign grants read")
					}
					// Warm account state in its legitimate tenant, then present an
					// inconsistent signed subject/tenant. The cache cannot cross scope.
					if _, err := auth.CurrentPwdVersion(tenant.WithTenant(context.Background(), targetTenant), actors[targetTenant].ID); err != nil {
						t.Fatal(err)
					}
					inconsistent, err := mgr.IssueAccessEnterprise(actors[targetTenant].ID, "admin", "fixture@example.com", time.Minute, 0, "inconsistent", tid, fullPerms)
					if err != nil {
						t.Fatal(err)
					}
					if w := request("GET", "/api/v1/admin/users", inconsistent, targetTenant); w.Code != 401 {
						t.Fatalf("foreign subject accepted: %d", w.Code)
					}
					if rows, total, err := audits.FindByUserIDPaginated(ctx, u.ID, 1, 20); err != nil || total != 0 || len(rows) != 0 {
						t.Fatal("foreign audit owner")
					}
					if got, err := tokens.FindByHash(ctx, "hash-"+targetTenant); err != nil || got != nil {
						t.Fatal("foreign token")
					}
					if got, err := sessions.FindByID(ctx, "session-"+targetTenant); err != nil || got != nil {
						t.Fatal("foreign session")
					}
					if got, err := passkeys.FindByCredentialID(ctx, []byte("credential-"+targetTenant)); err != nil || got != nil {
						t.Fatal("foreign passkey")
					}
					if got, err := devices.FindByDeviceHash(ctx, "device-"+targetTenant); err != nil || got != nil {
						t.Fatal("foreign device")
					}
					if got, err := oauth.FindByProviderAndProviderUserID(ctx, "google", "subject-"+targetTenant); err != nil || got != nil {
						t.Fatal("foreign oauth")
					}
					if got, err := totp.FindByUserID(ctx, u.ID); err != nil || got != nil {
						t.Fatal("foreign factor")
					}
					var persisted models.User
					if err := db.First(&persisted, u.ID).Error; err != nil {
						t.Fatal(err)
					}
					if persisted.FullName != "canary-"+targetTenant || persisted.Password != "hash" || persisted.PwdVersion != before.PwdVersion || persisted.LockedUntil != nil {
						t.Fatal("foreign effects persisted")
					}
				})
			}
			// Subject ownership is required even inside the same tenant.
			if w := request("DELETE", "/api/v1/auth/sessions/session-"+tid, full, "spoof"); w.Code != 404 {
				t.Fatalf("another subject's session revoked: %d", w.Code)
			}
			if w := request("GET", "/api/v1/auth/sessions", full, "spoof"); w.Code != 200 || strings.Contains(w.Body.String(), "session-"+tid) {
				t.Fatal("another subject's session listed")
			}
			if w := request("GET", "/api/v1/auth/me", full, "spoof"); w.Code != 200 || !strings.Contains(w.Body.String(), "actor@example.com") {
				t.Fatalf("same-tenant subject read: %d %s", w.Code, w.Body.String())
			}
			for _, path := range []string{"/users", "/sessions", "/audit-log/export?format=csv", "/audit-log/export?format=ndjson"} {
				w := request(http.MethodGet, "/api/v1/admin"+path, full, "spoof")
				if w.Code != 200 {
					t.Fatalf("same-tenant read %s: %d %s", path, w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "canary-"+tid) && !strings.Contains(path, "/users") {
					t.Fatalf("own canary missing: %s", w.Body.String())
				}
				for _, foreign := range tenants {
					if foreign != tid && strings.Contains(w.Body.String(), "canary-"+foreign) {
						t.Fatal("foreign read/export canary")
					}
				}
			}
			for _, op := range []string{"lock", "unlock", "unlock", "force-logout"} {
				w := request(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/%s", targets[tid].ID, op), full, "spoof")
				if w.Code != 200 {
					t.Fatalf("same-tenant %s: %d %s", op, w.Code, w.Body.String())
				}
			}
			var own models.User
			if err := db.First(&own, targets[tid].ID).Error; err != nil {
				t.Fatal(err)
			}
			if own.PwdVersion != 1 || own.LockedUntil != nil {
				t.Fatal("legitimate mutations missing")
			}
			family, err := tokens.FindByHash(ctx, "hash-"+tid)
			if err != nil || family == nil || !family.Revoked {
				t.Fatal("same-tenant token not revoked")
			}
			sess, err := sessions.FindByID(ctx, "session-"+tid)
			if err != nil || sess == nil || !sess.Revoked {
				t.Fatal("same-tenant session not revoked")
			}
			// Lack of permissions is checked before IDs and cannot be enlarged by role or DB.
			for _, grants := range [][]string{nil, {}, {"*"}, {"USERS:WRITE"}} {
				denied := issue(t, tid, "admin", grants)
				for _, route := range []struct{ method, path string }{{"GET", "/users"}, {"GET", "/sessions"}, {"GET", "/audit-log/export"}, {"POST", fmt.Sprintf("/users/%d/lock", targets[tid].ID)}, {"POST", fmt.Sprintf("/users/%d/unlock", targets[tid].ID)}, {"POST", fmt.Sprintf("/users/%d/force-logout", targets[tid].ID)}} {
					if w := request(route.method, "/api/v1/admin"+route.path, denied, "B"); w.Code != 403 {
						t.Fatalf("ungranted operation %s: %d", route.path, w.Code)
					}
					if w := request(route.method, "/api/v1/admin"+route.path, "", "B"); w.Code != 401 {
						t.Fatalf("unauthenticated operation: %d", w.Code)
					}
				}
			}
			for _, path := range []string{"/users", "/sessions", "/audit-log/export"} {
				if w := request("GET", "/api/v1/admin"+path, writer, "B"); w.Code != 403 {
					t.Fatal("users:write expanded to read/export")
				}
			}
			if got, err := users.FindByEmail(ctx, "target@example.com"); err != nil || got == nil || got.ID != targets[tid].ID {
				t.Fatal("overlapping email selected foreign tenant")
			}
			if got, err := users.FindByUsername(ctx, "target"); err != nil || got == nil || got.ID != targets[tid].ID {
				t.Fatal("overlapping username selected foreign tenant")
			}
			if w := request("GET", "/api/v1/platform/users", full, "B"); w.Code != 404 {
				t.Fatal("platform authority exposed")
			}
		})
	}
}
