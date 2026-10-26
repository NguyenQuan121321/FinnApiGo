package handlers_test

import (
	"context"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/routes"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestF03ReviewRecoveryHTTPAdmissionFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&models.User{}, &models.AuditLog{}, &models.AuditHead{}, &models.AuditOutbox{}, &models.AuditBoundary{}); err != nil {
		t.Fatal(err)
	}
	users := repositories.NewUserRepository(db)
	u := &models.User{Username: "synthetic-recovery", Email: "synthetic-recovery@example.com", IsActive: true}
	if err = users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	repo := repositories.NewAuditRepository(db)
	writer := services.NewAsyncAuditWriter(repo, repo, config.AuditConfig{BufferSize: 1, FlushBatch: 10})
	defer writer.Close()
	if err = db.Exec("CREATE TRIGGER review_reject BEFORE INSERT ON audit_outboxes BEGIN SELECT RAISE(ABORT, 'synthetic admission failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	svc := services.NewAuthService(users, nil, nil, writer, nil, jwt.NewJWTManager("public synthetic review key", "finnapigo"), config.AuthConfig{BcryptCost: 4}, config.RateLimitConfig{}, config.JWTConfig{ResetTTL: time.Minute, VerifyTTL: time.Minute}, nil, nil, nil, nil, nil)
	if err = svc.ForgotPassword(context.Background(), u.Email, ""); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("service expected audit failure, got %v", err)
	}
	if err = svc.ResendVerifyEmail(context.Background(), u.Email, ""); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("resend expected audit failure, got %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := handlers.NewAuthHandler(svc, nil)
	r := gin.New()
	r.POST("/forgot", h.ForgotPassword)
	r.POST("/resend", h.ResendVerifyEmail)
	for _, path := range []string{"/forgot", "/resend"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"email":"synthetic-recovery@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 503 {
			t.Errorf("%s: got HTTP%d, want503 for real admission failure; response=%s", path, w.Code, w.Body.String())
		}
	}
	var n int64
	if err = db.Model(&models.AuditOutbox{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	t.Logf("durable outbox rows=%d", n)
}

// Only the external transport is observed. Public routing, rate limits, service,
// durable admission and repository are the real implementations.
type recoveryDelivery struct {
	services.Notifier
	tokens []string
}

func (n *recoveryDelivery) SendPasswordReset(_ context.Context, _, token string) error {
	n.tokens = append(n.tokens, token)
	return nil
}
func (n *recoveryDelivery) SendEmailVerification(_ context.Context, _, token string) error {
	n.tokens = append(n.tokens, token)
	return nil
}

func TestF03RecoveryPublicRoutesPrivacyAndRateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, unavailable := range []bool{false, true} {
		for _, path := range []string{"forgot-password", "resend-verification"} {
			t.Run(path+"/unavailable="+strconv.FormatBool(unavailable), func(t *testing.T) {
				db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
				if err != nil {
					t.Fatal(err)
				}
				pool, err := db.DB()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = pool.Close() }()
				pool.SetMaxOpenConns(1)
				if err := db.AutoMigrate(&models.User{}, &models.AuditLog{}, &models.AuditHead{}, &models.AuditOutbox{}, &models.AuditBoundary{}); err != nil {
					t.Fatal(err)
				}
				users := repositories.NewUserRepository(db)
				for _, verified := range []bool{false, true} {
					email := "known@example.com"
					if verified {
						email = "verified@example.com"
					}
					if err := users.Create(context.Background(), &models.User{Username: email, Email: email, IsActive: true, IsEmailVerified: verified}); err != nil {
						t.Fatal(err)
					}
				}
				repo := repositories.NewAuditRepository(db)
				writer := services.NewAsyncAuditWriter(repo, repo, config.AuditConfig{BufferSize: 1, FlushBatch: 10})
				defer writer.Close()
				if unavailable {
					if err := db.Exec("CREATE TRIGGER review_reject BEFORE INSERT ON audit_outboxes BEGIN SELECT RAISE(ABORT, 'synthetic admission failure'); END").Error; err != nil {
						t.Fatal(err)
					}
				}
				kv := store.NewInMemoryStore(time.Minute)
				defer kv.Close()
				notify := &recoveryDelivery{}
				mgr := jwt.NewJWTManager("public synthetic review key", "finnapigo")
				svc := services.NewAuthService(users, nil, nil, writer, kv, mgr, config.AuthConfig{BcryptCost: 4}, config.RateLimitConfig{VerifyResendPerEmailMax: 1, VerifyResendWindow: time.Minute}, config.JWTConfig{ResetTTL: time.Minute, VerifyTTL: time.Minute}, notify, nil, nil, nil, nil)
				limiter := middleware.NewRateLimiter(0.001, 20, time.Minute)
				defer limiter.Close()
				r := routes.Register(routes.Deps{Auth: handlers.NewAuthHandler(svc, nil), MFA: handlers.NewMFAHandler(nil, nil, 0), JWT: mgr, RateLimit: limiter})
				request := func(email string) *httptest.ResponseRecorder {
					t.Helper()
					req := httptest.NewRequest("POST", "/api/v1/auth/"+path, strings.NewReader(`{"email":"`+email+`"}`))
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)
					return w
				}
				var body string
				for _, email := range []string{"known@example.com", "unknown@example.com", "verified@example.com", "unknown@mailinator.com"} {
					before := len(notify.tokens)
					w := request(email)
					want := 200
					if unavailable {
						want = 503
					}
					if w.Code != want {
						t.Fatalf("%s: HTTP%d want%d", email, w.Code, want)
					}
					if body == "" {
						body = w.Body.String()
					}
					if w.Body.String() != body {
						t.Fatal("account existence changed public response")
					}
					emitted := !unavailable && (email == "known@example.com" || (path == "forgot-password" && email == "verified@example.com"))
					if (len(notify.tokens) > before) != emitted {
						t.Fatal("credential delivery escaped required admission or eligible delivery missing")
					}
					for _, token := range notify.tokens {
						if token == "" || strings.Contains(w.Body.String(), token) {
							t.Fatal("credential missing or exposed over HTTP")
						}
					}
				}
				if path == "resend-verification" {
					for _, email := range []string{"known@example.com", "unknown@example.com", "verified@example.com"} {
						if w := request(email); w.Code != 429 {
							t.Fatalf("per-email limit lost: %d", w.Code)
						}
					}
				}
				// The public middleware still caps both endpoints, including outages.
				for i := 0; i < 21; i++ {
					request("unknown@example.com")
				}
				if w := request("unknown@example.com"); w.Code != 429 {
					t.Fatal("public IP limiter lost")
				}
			})
		}
	}
}
