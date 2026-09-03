// Package apidrift keeps docs/openapi.yaml (the API contract of record, A1)
// in lockstep with the routes actually registered by internal/routes. The
// test builds the real router and fails when a route is missing from the
// spec or the spec documents an endpoint that no longer exists. It runs in
// the default CI test job — no database needed.
package apidrift

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/metrics"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/routes"
)

// TestOpenAPIMatchesRegisteredRoutes — bidirectional drift check (A1).
func TestOpenAPIMatchesRegisteredRoutes(t *testing.T) {
	router := buildRealRouter()

	// ---- actual routes: "METHOD /path" ----
	actual := map[string]bool{}
	for _, r := range router.Routes() {
		actual[r.Method+" "+ginToOpenAPI(r.Path)] = true
	}

	// ---- documented operations from docs/openapi.yaml ----
	documented := parseOpenAPIOperations(t, specPath(t))

	missing := difference(actual, documented)
	extra := difference(documented, actual)

	for _, op := range missing {
		t.Errorf("route %q is registered but MISSING from docs/openapi.yaml", op)
	}
	for _, op := range extra {
		t.Errorf("operation %q is documented in docs/openapi.yaml but has NO registered route", op)
	}
	if len(missing)+len(extra) == 0 && len(actual) == 0 {
		t.Fatal("no routes discovered — the drift check itself is broken")
	}
	t.Logf("contract drift check passed: %d operations in sync", len(actual))
}

// buildRealRouter registers every route (OAuth included) with inert handler
// values — the drift check never dispatches a request.
func buildRealRouter() *gin.Engine {
	deps := routes.Deps{
		Auth:                handlers.NewAuthHandler(nil, nil),
		OAuth:               handlers.NewOAuthHandler(nil),
		MFA:                 handlers.NewMFAHandler(nil, nil, 15*time.Minute),
		Sessions:            handlers.NewSessionHandler(nil),
		Passkey:             handlers.NewPasskeyHandler(nil),
		Admin:               handlers.NewAdminHandler(nil),
		TrustedDevice:       handlers.NewTrustedDeviceHandler(nil),
		Webhook:             handlers.NewWebhookHandler(nil),
		RateLimit:           middleware.NewRateLimiter(100, 200, time.Minute),
		MaxRequestBodyBytes: 1 << 20,
		Metrics:             metrics.Handler(nil),
		// The gated Swagger UI is a developer-experience companion, not part
		// of the contract — keep it out of the drift router regardless of any
		// default change in internal/config.
		SwaggerEnabled: false,
	}
	router := routes.Register(deps)
	_ = router.SetTrustedProxies(nil)
	return router
}

// ginToOpenAPI converts Gin's ":id" wildcard syntax to OpenAPI "{id}".
func ginToOpenAPI(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segs, "/")
}

// specPath resolves docs/openapi.yaml relative to this source file so the
// test is independent of the working directory.
func specPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source file for spec path resolution")
	}
	// thisFile: <repo>/internal/apidrift/apidrift_test.go
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "openapi.yaml")
}

var (
	pathRe = regexp.MustCompile(`^  (\/[^\s:]*\{[^}]*\}[^:]*|\/[^\s:]+):\s*$`)
	opRe   = regexp.MustCompile(`^    (get|post|put|patch|delete|head|options):\s*$`)
)

// parseOpenAPIOperations extracts "METHOD /path" pairs from the spec using a
// structural convention of THIS file: paths at two-space indent, operations
// at four-space indent. A malformed indentation therefore fails the check —
// which is the point of a drift gate. (Deliberately no YAML dependency: the
// go.mod allowlist is frozen.)
func parseOpenAPIOperations(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- fixed test-fixture path
	if err != nil {
		t.Fatalf("open spec: %v", err)
	}
	defer func() { _ = f.Close() }()

	ops := map[string]bool{}
	current := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := pathRe.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := opRe.FindStringSubmatch(line); m != nil && current != "" {
			ops[strings.ToUpper(m[1])+" "+current] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan spec: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("parsed 0 operations from docs/openapi.yaml — parser out of sync with spec layout")
	}
	return ops
}

// difference returns the sorted elements of a that are not in b.
func difference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
