package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func corsRouter(t *testing.T, origins []string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(origins))
	r.POST("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	return r
}

func TestCORS_AllowedOrigin_PreflightAndActual(t *testing.T) {
	r := corsRouter(t, []string{"http://localhost:5500"})

	// Preflight: OPTIONS with the preflight markers → 204 + full header set.
	req := httptest.NewRequest(http.MethodOptions, "/ping", nil)
	req.Header.Set("Origin", "http://localhost:5500")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight: status=%d want=204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5500" {
		t.Fatal("preflight: missing ACAO for allowed origin")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" || w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight: missing allow headers/methods")
	}

	// Actual request: ACAO present, handler runs.
	req = httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.Header.Set("Origin", "http://localhost:5500")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "pong" {
		t.Fatalf("actual: status=%d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5500" {
		t.Fatal("actual: missing ACAO")
	}
}

func TestCORS_UnlistedOrigin_NoHeaders_No403Leak(t *testing.T) {
	r := corsRouter(t, []string{"http://localhost:5500"})
	req := httptest.NewRequest(http.MethodOptions, "/ping", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Unlisted origin: NO CORS headers at all (the browser does the blocking);
	// the server must never reflect the origin.
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unlisted origin must not receive ACAO headers")
	}
}

func TestCORS_NoOrigin_NonBrowserPassThrough(t *testing.T) {
	r := corsRouter(t, nil) // even with an empty allowlist, native clients work
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("no-Origin request must pass through untouched: status=%d", w.Code)
	}
}
