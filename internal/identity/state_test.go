package identity_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

func key(label string) string {
	b := sha256.Sum256([]byte("F02 public synthetic " + label))
	return base64.StdEncoding.EncodeToString(b[:])
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func manager(t *testing.T) *jwt.JWTManager {
	t.Helper()
	m, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: "HS256", CurrentID: "current", CurrentSecret: key("signing")})
	must(t, err)
	return m
}

func TestStateSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	must(t, err)
	conn, err := db.DB()
	must(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { must(t, conn.Close()) })
	must(t, db.AutoMigrate(&models.User{}, &models.Tenant{}, &models.Session{}, &models.AccessRevocation{}, &models.Permission{}, &models.Role{}, &models.RolePermission{}, &models.UserRole{}))
	s := store.NewInMemoryStore(0)
	defer s.Close()
	runStateMatrix(t, db, s)
}

func runStateMatrix(t *testing.T, db *gorm.DB, s identity.SecurityStore) {
	m := manager(t)
	a := &identity.Authority{DB: db, Store: s}
	perms := []string{"chat:read", "users:read"}
	foreign := models.Tenant{ID: "foreign", Slug: "foreign", Name: "Foreign tenant", IsActive: true}
	must(t, db.Where("id = ?", foreign.ID).FirstOrCreate(&foreign).Error)
	var pp []models.Permission
	for _, name := range perms {
		p := models.Permission{Name: name}
		must(t, db.Where("name = ?", name).FirstOrCreate(&p).Error)
		pp = append(pp, p)
	}
	for _, tid := range []string{"default", "tenant-a", "tenant-b"} {
		t.Run(tid, func(t *testing.T) {
			ctx := tenant.WithTenant(context.Background(), tid)
			tr := models.Tenant{ID: tid, Slug: tid, Name: tid, IsActive: true}
			must(t, db.Where("id = ?", tid).FirstOrCreate(&tr).Error)
			u := models.User{TenantID: tid, Username: "f02-" + tid, Email: tid + "@example.invalid", Password: "synthetic hash", IsActive: true, Role: "admin"}
			must(t, db.Create(&u).Error)
			other := models.User{TenantID: tid, Username: "f02-other-" + tid, Email: "other-" + tid + "@example.invalid", Password: "synthetic hash", IsActive: true}
			must(t, db.Create(&other).Error)
			sess := models.Session{ID: uuid.NewString(), TenantID: tid, UserID: u.ID, LastActiveAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
			must(t, db.Create(&sess).Error)
			r := models.Role{TenantID: tid, Name: "f02-role"}
			must(t, db.Create(&r).Error)
			for _, p := range pp {
				must(t, db.Create(&models.RolePermission{RoleID: r.ID, PermissionID: p.ID}).Error)
			}
			must(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: r.ID}).Error)
			tok, err := m.IssueAccessV1(u.ID, "admin", "", time.Minute, 0, 0, sess.ID, tid, perms)
			must(t, err)
			c, err := m.VerifyAccessV1(tok, jwt.JakeAudience)
			must(t, err)
			must(t, a.Check(context.Background(), c))
			t.Run("foreign tenant", func(t *testing.T) {
				clone := *c
				clone.TenantID = "foreign"
				if !errors.Is(a.Check(context.Background(), &clone), identity.ErrInactive) {
					t.Fatal("foreign state accepted")
				}
			})
			for name, delta := range map[string]map[string]any{"inactive": {"is_active": false}, "suspended": {"admin_suspended": true}, "credential version": {"pwd_version": 1}, "epoch": {"auth_epoch": 1}} {
				t.Run(name, func(t *testing.T) {
					must(t, db.Model(&u).Updates(delta).Error)
					if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
						t.Fatal("inactive/stale account accepted")
					}
					must(t, db.Model(&u).Updates(map[string]any{"is_active": true, "admin_suspended": false, "pwd_version": 0, "auth_epoch": 0}).Error)
				})
			}
			for name, delta := range map[string]map[string]any{"revoked session": {"revoked": true}, "expired session": {"expires_at": time.Now().Add(-time.Second)}, "foreign session": {"tenant_id": foreign.ID}, "other owner": {"user_id": other.ID}} {
				t.Run(name, func(t *testing.T) {
					must(t, db.Model(&sess).Updates(delta).Error)
					if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
						t.Fatal("invalid session accepted")
					}
					must(t, db.Model(&sess).Updates(map[string]any{"revoked": false, "expires_at": time.Now().Add(time.Hour), "tenant_id": tid, "user_id": u.ID}).Error)
				})
			}
			t.Run("tenant disabled", func(t *testing.T) {
				must(t, db.Model(&tr).Update("is_active", false).Error)
				if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
					t.Fatal("inactive tenant accepted")
				}
				must(t, db.Model(&tr).Update("is_active", true).Error)
			})
			t.Run("permission removed", func(t *testing.T) {
				rp := models.RolePermission{RoleID: r.ID, PermissionID: pp[0].ID}
				must(t, db.Delete(&rp).Error)
				if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
					t.Fatal("removed signed grant accepted")
				}
				must(t, db.Create(&rp).Error)
			})
			t.Run("unsigned added grant", func(t *testing.T) {
				clone := *c
				clone.Permissions = append(append([]string{}, perms...), "*")
				if !errors.Is(a.Check(ctx, &clone), identity.ErrInactive) {
					t.Fatal("wildcard accepted")
				}
			})
			t.Run("role epoch", func(t *testing.T) {
				extra := models.Role{TenantID: tid, Name: "f02-extra"}
				must(t, db.Create(&extra).Error)
				must(t, repositories.NewRBACRepository(db).AssignRoleToUser(ctx, u.ID, extra.ID))
				if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
					t.Fatal("role epoch not invalidated")
				}
				must(t, db.Model(&u).Update("auth_epoch", 0).Error)
			})
			runHTTPMatrix(t, m, a, tok, tid)
			t.Run("durable JTI", func(t *testing.T) {
				must(t, a.RevokeAccess(ctx, c.ID, time.Now().Add(jwt.KeyDrain)))
				if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
					t.Fatal("durable revoked JTI accepted")
				}
			})
			t.Run("suspension seam", func(t *testing.T) {
				must(t, a.Suspend(ctx, u.ID))
				if !errors.Is(a.Check(ctx, c), identity.ErrInactive) {
					t.Fatal("suspension accepted")
				}
				var current models.User
				must(t, db.First(&current, u.ID).Error)
				if !current.AdminSuspended || current.AuthEpoch != 1 || current.PwdVersion != 1 {
					t.Fatal("suspension counters missing")
				}
			})
		})
	}
}

func request(t *testing.T, h *identity.Handler, token, tid, secret, kid string, useTLS bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"token": token, "tenant_id": tid})
	must(t, err)
	r := gin.New()
	r.POST("/identity", h.Handle)
	req := httptest.NewRequest("POST", "/identity", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	req.Header.Set("X-Service-Key-ID", kid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func runHTTPMatrix(t *testing.T, m *jwt.JWTManager, a *identity.Authority, tok, tid string) {
	k := identity.ServiceKeys{CurrentID: "state-current", CurrentSecret: key("state"), PreviousID: "state-old", PreviousSecret: key("state-old"), PreviousUntil: time.Now().Add(time.Minute)}
	h := &identity.Handler{JWT: m, Authority: a, Keys: k}
	t.Run("actual TLS transport", func(t *testing.T) {
		r := gin.New()
		r.POST("/identity", h.Handle)
		server := httptest.NewTLSServer(r)
		defer server.Close()
		body, err := json.Marshal(map[string]string{"token": tok, "tenant_id": tid})
		must(t, err)
		req, err := http.NewRequestWithContext(context.Background(), "POST", server.URL+"/identity", strings.NewReader(string(body)))
		must(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+k.CurrentSecret)
		req.Header.Set("X-Service-Key-ID", k.CurrentID)
		resp, err := server.Client().Do(req)
		must(t, err)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 || resp.TLS == nil {
			t.Fatalf("TLS introspection status %d", resp.StatusCode)
		}
	})
	for _, permission := range []string{"users:read", "users:write"} {
		t.Run("live authority permission "+permission, func(t *testing.T) {
			r := gin.New()
			r.GET("/p", middleware.AuthMiddleware(m, nil, middleware.WithIdentityState(a.Check)), middleware.RequirePermission(permission, nil), func(c *gin.Context) {
				if c.GetString("tenant_id") != tid {
					t.Error("header selected tenant")
				}
				c.Status(200)
			})
			req := httptest.NewRequest("GET", "/p", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("X-Tenant-ID", "foreign")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			want := 200
			if permission == "users:write" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("status %d want %d", w.Code, want)
			}
		})
	}
	for _, tc := range []struct {
		name, token, tid, secret, kid string
		tls                           bool
		want                          int
	}{
		{"valid", tok, tid, k.CurrentSecret, k.CurrentID, true, 200}, {"missing service", tok, tid, "", k.CurrentID, true, 401}, {"wrong service", tok, tid, key("bad"), k.CurrentID, true, 401}, {"wrong service id", tok, tid, k.CurrentSecret, "wrong", true, 401},
		{"TLS required", tok, tid, k.CurrentSecret, k.CurrentID, false, 503}, {"foreign", tok, "foreign", k.CurrentSecret, k.CurrentID, true, 403}, {"invalid JWT", "bad", tid, k.CurrentSecret, k.CurrentID, true, 401}, {"previous service", tok, tid, k.PreviousSecret, k.PreviousID, true, 200},
	} {
		t.Run("HTTP "+tc.name, func(t *testing.T) {
			w := request(t, h, tc.token, tc.tid, tc.secret, tc.kid, tc.tls)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == 200 && strings.Contains(w.Body.String(), "email") {
				t.Fatal("unnecessary identity disclosed")
			}
		})
	}
	h.Keys.PreviousUntil = time.Now().Add(-time.Second)
	if w := request(t, h, tok, tid, k.PreviousSecret, k.PreviousID, true); w.Code != 401 {
		t.Fatal("expired service key accepted")
	}
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{{"inactive", identity.ErrInactive, 401}, {"unavailable", fmt.Errorf("dependency down"), 503}, {"valid", nil, 200}} {
		t.Run("middleware "+tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/p", middleware.AuthMiddleware(m, nil, middleware.WithIdentityState(func(context.Context, *jwt.Claims) error { return tc.err })), middleware.RequirePermission("users:read", nil), func(c *gin.Context) { c.Status(200) })
			req := httptest.NewRequest("GET", "/p", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("X-Tenant-ID", "foreign")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("%d want %d", w.Code, tc.want)
			}
		})
	}
}

type faultStore struct {
	err   error
	allow bool
}

func (s faultStore) Revoked(context.Context, string, string) (bool, error) { return false, s.err }
func (s faultStore) Admit(context.Context, string, int64, time.Duration) (bool, error) {
	return s.allow, s.err
}
func TestHTTPFailClosedAdmission(t *testing.T) {
	m := manager(t)
	k := identity.ServiceKeys{CurrentID: "state", CurrentSecret: key("state")}
	for _, tc := range []struct {
		s    identity.SecurityStore
		want int
	}{{faultStore{err: errors.New("down")}, 503}, {faultStore{}, 429}, {nil, 503}} {
		h := &identity.Handler{JWT: m, Authority: &identity.Authority{Store: tc.s}, Keys: k}
		w := request(t, h, "bad", "default", k.CurrentSecret, k.CurrentID, true)
		if w.Code != tc.want {
			t.Fatalf("status %d want %d", w.Code, tc.want)
		}
	}
}

func TestServiceKeyPolicy(t *testing.T) {
	base := identity.ServiceKeys{CurrentID: "service", CurrentSecret: key("state")}
	must(t, identity.ValidateServiceKeys(base, key("signing")))
	for _, mutate := range []func(*identity.ServiceKeys){func(k *identity.ServiceKeys) { k.CurrentID = "" }, func(k *identity.ServiceKeys) { k.CurrentSecret = "short" }, func(k *identity.ServiceKeys) { k.PreviousID = "old" }, func(k *identity.ServiceKeys) { k.PreviousSecret = key("old"); k.PreviousID = k.CurrentID }, func(k *identity.ServiceKeys) {
		k.PreviousSecret = key("old")
		k.PreviousID = "old"
		k.PreviousUntil = time.Now().Add(time.Hour)
	}} {
		k := base
		mutate(&k)
		if identity.ValidateServiceKeys(k) == nil {
			t.Fatal("bad service policy accepted")
		}
	}
	if identity.ValidateServiceKeys(base, base.CurrentSecret) == nil {
		t.Fatal("application key reused")
	}
	material, err := base64.StdEncoding.DecodeString(base.CurrentSecret)
	must(t, err)
	if identity.ValidateServiceKeys(base, hex.EncodeToString(material)) == nil {
		t.Fatal("resolved recovery key material reused")
	}
}
