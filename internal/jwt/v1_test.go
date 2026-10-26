package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// All keys/tokens in this suite are synthetic, derived from public test labels.
func fixtureKey(label string) string {
	b := sha256.Sum256([]byte(label))
	return base64.StdEncoding.EncodeToString(b[:])
}
func strictManager(t *testing.T) *JWTManager {
	t.Helper()
	m, err := NewConfiguredJWTManager(KeyConfig{Algorithm: "HS256", CurrentID: "synthetic-current", CurrentSecret: fixtureKey("F02 public synthetic current")})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestV1ConfigAndRotation(t *testing.T) {
	base := KeyConfig{Algorithm: "HS256", CurrentID: "new", CurrentSecret: fixtureKey("new")}
	for name, mutate := range map[string]func(*KeyConfig){
		"algorithm": func(c *KeyConfig) { c.Algorithm = "RS256" }, "missing id": func(c *KeyConfig) { c.CurrentID = "" }, "bad id": func(c *KeyConfig) { c.CurrentID = "url/key" }, "long id": func(c *KeyConfig) { c.CurrentID = strings.Repeat("a", 65) },
		"short": func(c *KeyConfig) { c.CurrentSecret = "short" }, "weak": func(c *KeyConfig) { c.CurrentSecret = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"partial previous": func(c *KeyConfig) { c.PreviousID = "old" }, "partial timestamp": func(c *KeyConfig) { c.PreviousLastIssued = time.Now() },
		"previous short": func(c *KeyConfig) { c.PreviousSecret = "short" }, "same key": func(c *KeyConfig) {
			c.PreviousSecret = c.CurrentSecret
			c.PreviousID = "old"
			c.PreviousLastIssued = time.Now().Add(-time.Second)
		},
		"same id": func(c *KeyConfig) {
			c.PreviousSecret = fixtureKey("old")
			c.PreviousID = c.CurrentID
			c.PreviousLastIssued = time.Now().Add(-time.Second)
		},
		"future": func(c *KeyConfig) {
			c.PreviousSecret = fixtureKey("old")
			c.PreviousID = "old"
			c.PreviousLastIssued = time.Now().Add(time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := NewConfiguredJWTManager(c); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	old, err := NewConfiguredJWTManager(KeyConfig{Algorithm: "HS256", CurrentID: "old", CurrentSecret: fixtureKey("old")})
	if err != nil {
		t.Fatal(err)
	}
	token, err := old.IssueAccessV1(1, "admin", "", time.Minute, 0, 0, "sid", "default", []string{})
	if err != nil {
		t.Fatal(err)
	}
	last := time.Now().Add(-time.Second)
	base.PreviousID, base.PreviousSecret, base.PreviousLastIssued = "old", fixtureKey("old"), last
	m, err := NewConfiguredJWTManager(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Verify(token); err != nil {
		t.Fatal("old key must work before retirement", err)
	}
	m.now = func() time.Time { return last.Add(KeyDrain) }
	if _, err = m.Verify(token); err == nil {
		t.Fatal("old key accepted at retirement")
	}
	newToken, err := m.IssueAccessV1(1, "admin", "", time.Minute, 0, 0, "sid", "default", nil)
	if err != nil {
		t.Fatal(err)
	}
	if peekKid(newToken) != "new" {
		t.Fatal("previous-key issuance continued")
	}
	if _, err = m.Issue(1, "admin", "", TokenTypeAccess, time.Minute); err == nil {
		t.Fatal("generic access issuance")
	}
	if _, err = m.IssueAccess(1, "admin", "", time.Minute, 0, "sid"); err == nil {
		t.Fatal("unscoped access issuance")
	}
	if _, err = m.IssueAccessEnterprise(1, "admin", "", time.Minute, 0, "sid", "default", nil); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{TokenTypeReset, TokenTypeEmailVerify, TokenTypeMFAPending, TokenTypeSudo, "service"} {
		tok, err := m.Issue(1, "admin", "", purpose, time.Minute, "default")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.VerifyAccessV1(tok, FinnAudience); err == nil {
			t.Fatalf("accepted %s as access", purpose)
		}
	}
	for _, args := range []struct {
		uid       uint
		ttl       time.Duration
		pv, epoch int64
		sid, tid  string
	}{
		{0, time.Minute, 0, 0, "s", "t"}, {1, 0, 0, 0, "s", "t"}, {1, time.Hour, 0, 0, "s", "t"}, {1, time.Minute, -1, 0, "s", "t"}, {1, time.Minute, 0, -1, "s", "t"}, {1, time.Minute, 0, 0, "", "t"}, {1, time.Minute, 0, 0, "s", ""},
	} {
		if _, err := m.IssueAccessV1(args.uid, "", "", args.ttl, args.pv, args.epoch, args.sid, args.tid, nil); err == nil {
			t.Fatal("bad issuance accepted")
		}
	}
}

func TestV1FreshPurposeIsolation(t *testing.T) {
	m := strictManager(t)
	for _, purpose := range []string{TokenTypeReset, TokenTypeEmailVerify, TokenTypeMFAPending, TokenTypeSudo, "service"} {
		t.Run(purpose, func(t *testing.T) {
			token, err := m.Issue(7, "user", "", purpose, time.Minute, "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			c, err := m.Verify(token)
			if err != nil || c.Type != purpose || c.TenantID != "tenant-a" || len(c.Audience) != 1 || c.Audience[0] != "finnapigo-purpose:"+purpose {
				t.Fatalf("valid fresh purpose failed: %v", err)
			}
			if _, err := m.VerifyAccessV1(token, FinnAudience); err == nil {
				t.Fatal("fresh purpose became broad access")
			}
			if _, err := m.VerifyAccessV1(token, JakeAudience); err == nil {
				t.Fatal("fresh purpose became Jake access")
			}
		})
	}
}

type contractFixture struct {
	Name, Token, Tenant, Audience string
	Active                        bool
	Now                           int64
}

func TestV1CrossLanguageContract(t *testing.T) {
	m := strictManager(t)
	now := time.Now().Truncate(time.Second)
	token, err := m.IssueAccessV1(7, "admin", "", MaxAccessTTL, 0, 0, "synthetic-session", "default", []string{"chat:read", "users:read"})
	if err != nil {
		t.Fatal(err)
	}
	var payload jwtlib.MapClaims
	if _, _, err := jwtlib.NewParser().ParseUnverified(token, &payload); err != nil {
		t.Fatal(err)
	}
	// Pin both implementations to the actual issuance second. Wall time
	// crossing a second must not turn the +31s negative into valid +30s skew.
	now = time.Unix(int64(payload["iat"].(float64)), 0)
	m.now = func() time.Time { return now }
	fixtures := []contractFixture{}
	add := func(name, tok, tid, aud string, want bool) {
		t.Helper()
		_, err := m.VerifyAccessV1(tok, aud)
		if (err == nil) != want {
			t.Fatalf("%s Go accepted=%v want=%v: %v", name, err == nil, want, err)
		}
		fixtures = append(fixtures, contractFixture{name, tok, tid, aud, want, now.Unix()})
	}
	add("valid default", token, "default", JakeAudience, true)
	add("valid Finn", token, "default", FinnAudience, true)
	add("unknown audience selector", token, "default", "other", false)
	for _, tid := range []string{"tenant-a", "tenant-b"} {
		tok, err := m.IssueAccessV1(7, "user", "", time.Minute, 0, 1, "synthetic-session", tid, []string{"chat:write"})
		if err != nil {
			t.Fatal(err)
		}
		add("valid "+tid, tok, tid, JakeAudience, true)
	}
	for _, perms := range [][]string{nil, {}, {"*"}, {"chat:*"}, {"users:read"}} {
		tok, err := m.IssueAccessV1(7, "admin", "", time.Minute, 0, 0, "synthetic-session", "default", perms)
		if err != nil {
			t.Fatal(err)
		}
		add("Finn-only "+strings.Join(perms, ","), tok, "default", JakeAudience, false)
		add("Finn valid "+strings.Join(perms, ","), tok, "default", FinnAudience, true)
	}
	sign := func(p jwtlib.MapClaims, alg jwtlib.SigningMethod, kid string, key any) string {
		t.Helper()
		tok := jwtlib.NewWithClaims(alg, p)
		if kid != "" {
			tok.Header["kid"] = kid
		}
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	clone := func() jwtlib.MapClaims {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var c jwtlib.MapClaims
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	ambiguousNameFixtures(t, m, payload, add)
	for _, claim := range []string{"contract_ver", "iss", "aud", "sub", "uid", "type", "tid", "exp", "iat", "nbf", "jti", "sid", "pwdver", "auth_epoch", "perms"} {
		for _, null := range []bool{false, true} {
			c := clone()
			if null {
				c[claim] = nil
			} else {
				delete(c, claim)
			}
			add("missing/null "+claim, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
		}
	}
	for name, value := range map[string]any{"iss": "wrong", "aud": []string{"other"}, "sub": "8", "uid": 8, "type": "reset", "tid": " ", "contract_ver": 2, "pwdver": -1, "auth_epoch": -1, "perms": "chat:read", "sid": "", "jti": "", "exp": now.Unix() + 901, "iat": now.Unix() + 31, "nbf": now.Unix() + 31} {
		c := clone()
		c[name] = value
		add("wrong "+name, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
	}
	for name, value := range map[string]any{"tenant_id": "other", "permissions": []string{"*"}, "roles": []string{"admin"}, "scopes": []string{"*"}, "id": "alias"} {
		c := clone()
		c[name] = value
		add("conflicting "+name, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
	}
	for name, value := range map[string]any{"aud": []string{FinnAudience, FinnAudience}, "uid": "7", "exp": now.Unix() - 31, "nbf": now.Unix() - 1} {
		c := clone()
		c[name] = value
		add("boundary "+name, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
	}
	for _, v := range []any{[]any{nil}, []any{7}, []string{FinnAudience, "other"}, []string{JakeAudience}, []string{FinnAudience, JakeAudience, JakeAudience}} {
		c := clone()
		name := "aud"
		if _, ok := v.([]any); ok {
			name = "perms"
		}
		c[name] = v
		add("ill-typed/foreign array "+name, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
	}
	future := clone()
	future["iat"], future["nbf"] = now.Unix()+30, now.Unix()+30
	add("exact future skew", sign(future, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, true)
	add("unknown kid", sign(clone(), jwtlib.SigningMethodHS256, "unknown", m.current), "default", JakeAudience, false)
	add("missing kid", sign(clone(), jwtlib.SigningMethodHS256, "", m.current), "default", JakeAudience, false)
	add("wrong key", sign(clone(), jwtlib.SigningMethodHS256, m.currentKid, []byte(fixtureKey("different"))), "default", JakeAudience, false)
	add("wrong algorithm", sign(clone(), jwtlib.SigningMethodHS384, m.currentKid, m.current), "default", JakeAudience, false)
	add("malformed", "not.jwt", "default", JakeAudience, false)
	for _, raw := range []string{`{"uid":7,"uid":8}`, `[]`, `{"a":`, `{} {}`, `{"a":1} trailing`} {
		if _, err := uniqueObject([]byte(raw)); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	duplicatePayload := strings.Replace(string(mustJSON(t, payload)), `"uid":7`, `"uid":7,"uid":8`, 1)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"synthetic-current"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString([]byte(duplicatePayload))
	mac := hmac.New(sha256.New, m.current)
	_, _ = mac.Write([]byte(input))
	add("duplicate uid", input+"."+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), "default", JakeAudience, false)
	for _, p := range []string{TokenTypeReset, TokenTypeEmailVerify, TokenTypeMFAPending, TokenTypeSudo, "service"} {
		c := clone()
		c["type"] = p
		add("purpose "+p, sign(c, jwtlib.SigningMethodHS256, m.currentKid, m.current), "default", JakeAudience, false)
	}
	// Python additionally enforces request tenant equality (Go state/HTTP tests do likewise).
	fixtures = append(fixtures, contractFixture{"foreign request tenant", token, "foreign", JakeAudience, false, now.Unix()})
	previousSecret := fixtureKey("F02 public synthetic previous")
	previousBytes, err := DecodeStrongKey(previousSecret)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := NewConfiguredJWTManager(KeyConfig{Algorithm: "HS256", CurrentID: m.currentKid, CurrentSecret: base64.StdEncoding.EncodeToString(m.current), PreviousID: "synthetic-previous", PreviousSecret: previousSecret, PreviousLastIssued: now})
	if err != nil {
		t.Fatal(err)
	}
	previousToken := sign(clone(), jwtlib.SigningMethodHS256, "synthetic-previous", previousBytes)
	if _, err := rot.VerifyAccessV1(previousToken, JakeAudience); err != nil {
		t.Fatal(err)
	}
	fixtures = append(fixtures, contractFixture{"rotation previous overlap", previousToken, "default", JakeAudience, true, now.Unix()})
	// A holder of the retired HMAC key cannot extend authority by signing a fresh
	// otherwise-valid token after the deadline. Retirement beats its fresh exp.
	retire := now.Add(KeyDrain)
	forged := clone()
	forged["iat"], forged["nbf"], forged["exp"] = retire.Unix(), retire.Unix(), retire.Add(MaxAccessTTL).Unix()
	retiredToken := sign(forged, jwtlib.SigningMethodHS256, "synthetic-previous", previousBytes)
	rot.now = func() time.Time { return retire }
	if _, err := rot.VerifyAccessV1(retiredToken, JakeAudience); err == nil {
		t.Fatal("retired key signed fresh token accepted")
	}
	fixtures = append(fixtures, contractFixture{"rotation retired fresh forgery", retiredToken, "default", JakeAudience, false, retire.Unix()})
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic-v1.json")
	b, err := json.MarshalIndent(map[string]any{"provenance": "Go-issued F02 synthetic fixtures; no production data; reference policy is not Jake runtime", "keys": map[string]string{m.currentKid: base64.StdEncoding.EncodeToString(m.current), "synthetic-previous": previousSecret}, "retired": map[string]int64{"synthetic-previous": retire.Unix()}, "fixtures": fixtures}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("F02_EMIT_FIXTURES") == "1" {
		t.Log("F02_FIXTURES_BASE64=" + base64.StdEncoding.EncodeToString(b))
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	cmd := exec.Command(python, filepath.Join(filepath.Dir(source), "../../tests/identitycontract/verifier.py"), path) // #nosec G204 -- fixed interpreter/script, synthetic fixture path.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python contract: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
