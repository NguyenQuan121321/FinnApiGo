package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedRawFixture(m *JWTManager, header, payload string) string {
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, m.current)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestV1ProtectedTokenNames(t *testing.T) {
	m := strictManager(t)
	header := `{"alg":"HS256","kid":"synthetic-current"}`
	for _, parts := range [][2]string{{"[]", "{}"}, {"{}", "[]"}, {`{"kid":1,"kid":2}`, "{}"}, {"{}", `{"uid":1,"uid":2}`}, {"{", "{}"}, {"{}", "{"}} {
		if err := validateTokenNames(signedRawFixture(m, parts[0], parts[1])); err == nil {
			t.Fatal("ambiguous/nonobject JSON accepted")
		}
	}
	for _, token := range []string{"missing.parts", "!.e30.signature", "e30.!.signature"} {
		if err := validateTokenNames(token); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
	// Purpose-token verification uses the same name guard before decoding too.
	purpose, err := m.Issue(7, "user", "", TokenTypeSudo, time.Minute, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(purpose, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TID", "UID", "TYPE", "SUB", "ſid"} {
		t.Run(name, func(t *testing.T) {
			payload := strings.TrimSuffix(string(raw), "}") + "," + string(mustJSON(t, name)) + `:"conflicting"}`
			if _, err := m.Verify(signedRawFixture(m, header, payload)); err == nil {
				t.Fatal("purpose case alias accepted")
			}
		})
	}
}

// Keep these test lists independent of the implementation allowlists so adding
// or accidentally removing a protected name cannot silently shrink coverage.
func ambiguousNameFixtures(t *testing.T, m *JWTManager, payload map[string]any, add func(string, string, string, string, bool)) {
	t.Helper()
	header := `{"alg":"HS256","kid":"synthetic-current","typ":"JWT"}`
	base := string(mustJSON(t, payload))
	for _, name := range []string{"contract_ver", "iss", "aud", "sub", "uid", "type", "tid", "exp", "iat", "nbf", "jti", "sid", "pwdver", "auth_epoch", "perms", "role", "email"} {
		value, present := payload[name]
		if !present { // email is an optional typed field.
			value = "synthetic@example.invalid"
		}
		canonical := string(mustJSON(t, name)) + ":" + string(mustJSON(t, value))
		without := map[string]any{}
		for k, v := range payload {
			if k != name {
				without[k] = v
			}
		}
		body := string(mustJSON(t, without))
		body = strings.TrimSuffix(body, "}")
		variants := []string{strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:]}
		if strings.Contains(name, "s") {
			variants = append(variants, strings.ReplaceAll(name, "s", "ſ")) // Go Unicode case folding.
		}
		for _, alias := range variants {
			for _, aliasValue := range []any{value, "conflicting-authority", map[string]any{"malformed": true}} {
				member := string(mustJSON(t, alias)) + ":" + string(mustJSON(t, aliasValue))
				for _, members := range []string{canonical + "," + member, member + "," + canonical, member} {
					raw := body + "," + members + "}"
					add("protected spelling "+name+"/"+alias, signedRawFixture(m, header, raw), "default", JakeAudience, false)
				}
			}
		}
		for _, v := range []any{value, "different", map[string]any{"malformed": true}} {
			duplicate := string(mustJSON(t, name)) + ":" + string(mustJSON(t, v))
			add("exact duplicate "+name, signedRawFixture(m, header, body+","+canonical+","+duplicate+"}"), "default", JakeAudience, false)
		}
		without[name] = map[string]any{"malformed": true}
		add("malformed protected "+name, signedRawFixture(m, header, string(mustJSON(t, without))), "default", JakeAudience, false)
	}
	for _, alias := range []string{"tenant_id", "permissions", "roles", "scopes", "id"} {
		for _, name := range []string{alias, strings.ToUpper(alias)} {
			add("forbidden alias "+name, signedRawFixture(m, header, strings.TrimSuffix(base, "}")+","+string(mustJSON(t, name))+`:"alias"}`), "default", JakeAudience, false)
		}
	}
	for name, value := range map[string]any{"alg": "HS256", "kid": m.currentKid, "typ": "JWT", "cty": "JWT", "crit": []string{}, "jku": "synthetic.invalid", "jwk": map[string]any{}, "x5u": "synthetic.invalid", "x5c": []string{}, "x5t": "synthetic", "x5t#S256": "synthetic", "b64": true} {
		var h map[string]any
		if err := json.Unmarshal([]byte(header), &h); err != nil {
			t.Fatal(err)
		}
		delete(h, name)
		rest := strings.TrimSuffix(string(mustJSON(t, h)), "}")
		canonical := string(mustJSON(t, name)) + ":" + string(mustJSON(t, value))
		for _, alias := range []string{strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:]} {
			member := string(mustJSON(t, alias)) + ":" + string(mustJSON(t, value))
			for _, members := range []string{canonical + "," + member, member + "," + canonical, member} {
				add("header spelling "+name+"/"+alias, signedRawFixture(m, rest+","+members+"}", base), "default", JakeAudience, false)
			}
		}
		add("header duplicate "+name, signedRawFixture(m, rest+","+canonical+","+canonical+"}", base), "default", JakeAudience, false)
	}
	add("benign extensions", signedRawFixture(m, strings.TrimSuffix(header, "}")+`,"example_extension":1,"EXAMPLE_EXTENSION":2}`, strings.TrimSuffix(base, "}")+`,"example_extension":{"value":1},"EXAMPLE_EXTENSION":2}`), "default", JakeAudience, true)
}
