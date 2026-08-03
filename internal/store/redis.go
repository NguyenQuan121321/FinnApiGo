package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore is the multi-instance Store backend (§1.3 better-fix, §7).
//
// It implements the same Store contract as InMemoryStore but keeps all state
// in Redis, so rate-limit counters, velocity windows, and single-use-token
// (jti) markers are SHARED and consistent across every server instance. This
// is what makes the per-account/per-IP limits added in §2/§3/§5 correct under
// horizontal scaling — each instance no longer enforces its own independent
// quota.
//
// Semantics mirror InMemoryStore:
//   - Get: missing/expired key → (nil,false).
//   - Set: ttl<=0 means no expiry.
//   - SetNX: writes only if absent; atomic via SET NX PX.
//   - IncrBy: missing treated as 0; ttl is refreshed on every call so the
//     window is sliding (matches the in-memory behavior tests rely on).
type RedisStore struct {
	client redis.UniversalClient
	ctx    context.Context // background ctx for fire-and-forget calls
}

// NewRedisStore wraps an existing redis client. The caller owns the client's
// lifecycle (pool close, etc.).
func NewRedisStore(client redis.UniversalClient) *RedisStore {
	return &RedisStore{client: client, ctx: context.Background()}
}

// NewRedisStoreFromURL is a convenience constructor that builds a client from a
// redis:// (or rediss:// / unix://) URL. Returns the store and a Close function
// the caller should defer.
func NewRedisStoreFromURL(url string) (*RedisStore, func() error, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, nil, fmt.Errorf("store: parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	return NewRedisStore(client), client.Close, nil
}

// Get returns the string value at key, or false if missing. Numeric counters
// written by IncrBy are returned as their string form; callers that use Get for
// jti markers only care about presence, not the value.
func (s *RedisStore) Get(key string) (any, bool) {
	v, err := s.client.Get(s.ctx, key).Result()
	if err != nil {
		// redis.Nil covers both "missing" and "expired" — either way: absent.
		return nil, false
	}
	return v, true
}

// Set writes value with ttl (<=0 = no expiry). Values are stored as strings;
// callers that need structured data should serialize first.
func (s *RedisStore) Set(key string, value any, ttl time.Duration) {
	str := toRedisValue(value)
	if ttl <= 0 {
		_ = s.client.Set(s.ctx, key, str, 0).Err()
		return
	}
	_ = s.client.Set(s.ctx, key, str, ttl).Err()
}

// SetNX writes only if the key is absent; returns whether it wrote. The NX flag
// makes this atomic — the exact primitive single-use token (jti) enforcement
// and fixed-window counters depend on.
func (s *RedisStore) SetNX(key string, value any, ttl time.Duration) bool {
	str := toRedisValue(value)
	ok, err := s.client.SetNX(s.ctx, key, str, ttl).Result()
	return err == nil && ok
}

// IncrBy atomically adds delta to the numeric value at key (missing = 0) and
// returns the new value. The TTL is refreshed on every call so the window is
// sliding, matching InMemoryStore's behavior.
//
// INCRBY is itself atomic; we follow it with PEXPIRE to (re)start the window.
// There is a tiny gap between the two (a crash between them leaves the counter
// without a TTL), which is acceptable for rate-limiting — the next IncrBy will
// re-apply the TTL. For true atomicity a Lua script would be used; kept simple
// here to stay dependency-light and match the in-memory semantics closely.
func (s *RedisStore) IncrBy(key string, delta int64, ttl time.Duration) int64 {
	n, err := s.client.IncrBy(s.ctx, key, delta).Result()
	if err != nil {
		return 0
	}
	if ttl > 0 {
		_ = s.client.PExpire(s.ctx, key, ttl).Err()
	}
	return n
}

// Delete removes the key (idempotent).
func (s *RedisStore) Delete(key string) {
	_ = s.client.Del(s.ctx, key).Err()
}

// toRedisValue coerces an arbitrary value into a string Redis can store. int64
// is rendered without quotes so IncrBy can operate on keys originally written
// by Set; everything else falls back to fmt.
func toRedisValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return fmt.Sprintf("%d", x)
	case int:
		return fmt.Sprintf("%d", x)
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}
