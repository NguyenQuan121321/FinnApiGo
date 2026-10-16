package store

import (
	"context"
	"time"
)

// Revoked and Admit are error-aware operations for the identity boundary.
func (s *RedisStore) Revoked(ctx context.Context, jti, sid string) (bool, error) {
	n, err := s.client.Exists(ctx, "denylist:jti:"+jti, "denylist:sid:"+sid).Result()
	return n > 0, err
}

func (s *RedisStore) Admit(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	n, err := incrWithExpireScript.Run(ctx, s.client, []string{key}, 1, window.Milliseconds()).Int64()
	return n <= limit, err
}

func (s *InMemoryStore) Revoked(_ context.Context, jti, sid string) (bool, error) {
	_, j := s.Get("denylist:jti:" + jti)
	_, f := s.Get("denylist:sid:" + sid)
	return j || f, nil
}

func (s *InMemoryStore) Admit(_ context.Context, key string, limit int64, window time.Duration) (bool, error) {
	return s.IncrBy(key, 1, window) <= limit, nil
}
