// Key management seam (K3). Logical key names are stable identifiers —
// "jwt", "jwt_previous", "recovery_codes" — decoupled from WHERE the raw
// key material lives:
//
//   - EnvKeyProvider: keys supplied via environment/config (the default;
//     zero moving parts, what every deployment so far used).
//   - FileKeyProvider: keys as hex files under one directory
//     (KEY_PROVIDER=file, KEY_DIR=...), e.g. Docker/Kubernetes mounted
//     secrets or a Vault agent-rendered template dir.
//
// A cloud KMS (Vault Transit, AWS KMS, GCP KMS) plugs in as a third
// implementation of KeyProvider — typically fetch-on-boot with a cached
// decrypt of the latest key version — without touching any call site.
// Binding a vendor SDK is deliberately out of tree: it is an operator
// decision, not a library one.
package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// KeyProvider resolves named key material at boot.
type KeyProvider interface {
	// Retrieve returns the raw bytes for a logical key name. Implementations
	// must not return the same backing slice twice (callers may zero it).
	Retrieve(name string) ([]byte, error)
}

// Key names used by this service.
const (
	KeyNameJWT           = "jwt"
	KeyNameJWTPrevious   = "jwt_previous"
	KeyNameRecoveryCodes = "recovery_codes"
)

// ErrKeyNotFound is returned when a provider cannot resolve a key name.
var ErrKeyNotFound = errors.New("crypto: key not found")

// EnvKeyProvider serves keys from an in-memory map, typically assembled by
// the config loader from environment variables. It is the default provider.
type EnvKeyProvider struct {
	keys map[string][]byte
}

// NewEnvKeyProvider builds a provider over a name → raw-bytes map. The map is
// copied; nil names or empty values are rejected at Retrieve time as absent.
func NewEnvKeyProvider(keys map[string][]byte) *EnvKeyProvider {
	cp := make(map[string][]byte, len(keys))
	for k, v := range keys {
		cp[k] = append([]byte(nil), v...)
	}
	return &EnvKeyProvider{keys: cp}
}

// Retrieve returns a copy of the key bytes for name.
func (p *EnvKeyProvider) Retrieve(name string) ([]byte, error) {
	v, ok := p.keys[name]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, name)
	}
	return append([]byte(nil), v...), nil
}

// FileKeyProvider reads keys from hex-encoded files named `<name>.key` under
// a fixed directory. Files are read once per Retrieve at boot — key material
// is not expected to change while the process runs.
//
// On UNIX the provider warns when a key file is readable by group/other:
// mounted-secret directories are expected to enforce tighter perms than the
// process can guarantee after the fact. Windows ACLs are not expressible as
// mode bits, so the check is skipped there.
type FileKeyProvider struct {
	dir string
}

// NewFileKeyProvider serves keys from dir.
func NewFileKeyProvider(dir string) *FileKeyProvider {
	return &FileKeyProvider{dir: dir}
}

// Retrieve reads dir/<name>.key, hex-decodes it (surrounding whitespace is
// trimmed), and validates the length for AES-256 keys.
func (p *FileKeyProvider) Retrieve(name string) ([]byte, error) {
	path := filepath.Join(p.dir, name+".key")
	raw, err := os.ReadFile(path) // #nosec G304 -- name is a fixed service identifier, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, path)
		}
		return nil, fmt.Errorf("crypto: read key file %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if info, serr := os.Stat(path); serr == nil && info.Mode().Perm()&0o077 != 0 {
			slog.Warn("crypto: key file permissions looser than 0600", "path", path, "mode", info.Mode().Perm().String())
		}
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("crypto: key file %s must be hex-encoded: %w", path, err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key file %s must decode to %d bytes, got %d", path, KeyLen, len(key))
	}
	return key, nil
}
