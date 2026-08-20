package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// StoreErrors counts backend failures (Redis unreachable, timeouts, ...) across
// every store operation. It is the availability metric backing the split
// failure semantics (A1): rate COUNTERS fail OPEN (a Redis outage must not
// become an auth outage) while single-use guards fail CLOSED. Exposed to
// Prometheus in the metrics phase; readable by tests and /healthz handlers.
var StoreErrors atomic.Int64

// incrWithExpireScript atomically increments a counter and anchors its TTL at
// the FIRST increment of a window: PEXPIRE fires only when the increment just
// created the key (n == delta). Later increments — including requests the
// limiter denies — never extend the window, so a counter always resets even
// under sustained traffic (C4); before, every call refreshed the TTL and a
// hammering client stayed 429-locked indefinitely.
var incrWithExpireScript = redis.NewScript(`
    local n = redis.call('INCRBY', KEYS[1], ARGV[1])
    if tonumber(ARGV[2]) > 0 and n == tonumber(ARGV[1]) then
        redis.call('PEXPIRE', KEYS[1], ARGV[2])
    end
    return n
`)

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
//   - IncrBy: missing treated as 0; the TTL anchors at the first increment
//     of a window (fixed-window semantics) and is NOT refreshed by later
//     increments (matches the in-memory behavior tests rely on).
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
// jti markers only care about presence, not the value. On backend failure it
// reports absent — readers treat "unknown" as the safe default for their
// semantics (counters read as zero = fail open; presence checks consult their
// durable backstop) and the error is counted in StoreErrors (A1).
func (s *RedisStore) Get(key string) (any, bool) {
	v, err := s.client.Get(s.ctx, key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			StoreErrors.Add(1)
			slog.Error("store: redis get failed", "key", key, "err", err)
		}
		return nil, false
	}
	return v, true
}

// Set writes value with ttl (<=0 = no expiry). Values are stored as strings;
// callers that need structured data should serialize first. Write failures
// are counted in StoreErrors and logged — the Store contract has no error
// return, so this is the only way an operator learns Redis is down.
func (s *RedisStore) Set(key string, value any, ttl time.Duration) {
	str := toRedisValue(value)
	if err := s.client.Set(s.ctx, key, str, ttl).Err(); err != nil {
		StoreErrors.Add(1)
		slog.Error("store: redis set failed", "key", key, "err", err)
	}
}

// SetNX writes only if the key is absent; returns whether it wrote. The NX flag
// makes this atomic — the exact primitive single-use token (jti) enforcement
// and fixed-window counters depend on. Errors return false (fail CLOSED):
// for a single-use guard, denying the write is always the safe outcome — a
// store outage must not let a consumed token replay (A1).
func (s *RedisStore) SetNX(key string, value any, ttl time.Duration) bool {
	str := toRedisValue(value)
	ok, err := s.client.SetNX(s.ctx, key, str, ttl).Result()
	if err != nil {
		StoreErrors.Add(1)
		slog.Error("store: redis setnx failed", "key", key, "err", err)
		return false
	}
	return ok
}

// IncrBy atomically adds delta to the numeric value at key (missing = 0) and
// returns the new value. The TTL is anchored at the first increment of a
// window — later increments do not extend it, so the counter always resets
// one TTL after the window started (fixed-window semantics, C4). INCRBY and
// the conditional PEXPIRE run as one Lua script, so the counter never
// survives without its window.
//
// On Redis failure it returns 0 — fail OPEN (A1). Every IncrBy use is a
// throttle (rate limits, velocity caps); returning 0 means "no limit known",
// callers let the request through, and the shared-path rate limiter
// additionally falls back to its process-local token bucket. Redis being
// down must not lock users out of authentication. This SUPERSEDES the
// earlier always-return-MaxInt64 decision: counters fail open, single-use
// guards (SetNX) stay fail closed.
func (s *RedisStore) IncrBy(key string, delta int64, ttl time.Duration) int64 {
	n, err := incrWithExpireScript.Run(s.ctx, s.client, []string{key},
		delta, ttl.Milliseconds()).Int64()
	if err != nil {
		StoreErrors.Add(1)
		slog.Error("store: redis incrby failed", "key", key, "err", err)
		return 0 // fail OPEN — throttle unknown, do not deny
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
