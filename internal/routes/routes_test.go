package routes

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
)

func TestRegisterSmokeAndLogRedaction(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	router := Register(Deps{
		Auth: handlers.NewAuthHandler(nil, nil), MFA: handlers.NewMFAHandler(nil),
		JWT: jwt.NewJWTManager("test-secret", "test"), RateLimit: middleware.NewRateLimiter(100, 100, time.Minute),
	})
	for _, tc := range []struct {
		path string
		want int
	}{{"/healthz", 200}, {"/missing", 404}} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s: status=%d", tc.path, w.Code)
		}
	}
	secret := "Bearer super-secret-token"
	password := "correct-horse-battery-staple"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"a@example.com","password":"`+password+`"}`))
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)
	logged, err := io.ReadAll(&logs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), secret) || strings.Contains(string(logged), password) {
		t.Fatalf("sensitive value leaked into logs: %s", logged)
	}
}
