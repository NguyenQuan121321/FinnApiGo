//go:build integration

package identity_test

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/store"
)

func TestF02RealAdapters(t *testing.T) {
	if os.Getenv("F02_MYSQL_ALLOW_CREATE_DROP") != "1" || os.Getenv("F02_MYSQL_ADMIN_DSN") == "" || os.Getenv("TEST_REDIS_URL") == "" {
		t.Fatal("BLOCKED: explicit disposable F02 MySQL and Redis inputs required")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("F02_MYSQL_ADMIN_DSN"))
	must(t, err)
	host, _, err := net.SplitHostPort(cfg.Addr)
	must(t, err)
	if cfg.Net != "tcp" || (host != "127.0.0.1" && host != "::1") || cfg.DBName != "" {
		t.Fatal("disposable loopback MySQL admin without existing schema required")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	must(t, err)
	t.Cleanup(func() { must(t, admin.Close()) })
	schema := "finnapigo_f02_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4")
	must(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP DATABASE `" + schema + "`"); must(t, err) })
	cfg.DBName = schema
	must(t, database.RunMigrations(cfg.FormatDSN()))
	v, dirty, err := database.MigrationsVersion(cfg.FormatDSN())
	must(t, err)
	if dirty || v != 5 {
		t.Fatalf("version=%d dirty=%v", v, dirty)
	}
	db, err := gorm.Open(mysqldriver.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Discard})
	must(t, err)
	conn, err := db.DB()
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	opts, err := redis.ParseURL(os.Getenv("TEST_REDIS_URL"))
	must(t, err)
	rh, _, err := net.SplitHostPort(opts.Addr)
	must(t, err)
	if rh != "127.0.0.1" && rh != "::1" {
		t.Fatal("loopback Redis required")
	}
	opts.DB = 15 // isolated from existing suites that flush the configured default DB.
	opts.MaxRetries = -1
	opts.DialTimeout = 200 * time.Millisecond
	opts.ReadTimeout = 200 * time.Millisecond
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	must(t, client.Ping(context.Background()).Err())
	s := store.NewRedisStore(client)
	runStateMatrix(t, db, s)
	if t.Failed() {
		t.Fatal("real durable state matrix failed; adapter acceptance incomplete")
	}
	ctx := context.Background()
	t.Run("Redis absence vs revocation", func(t *testing.T) {
		jti, sid := uuid.NewString(), uuid.NewString()
		r, err := s.Revoked(ctx, jti, sid)
		must(t, err)
		if r {
			t.Fatal("missing marked revoked")
		}
		must(t, client.Set(ctx, "denylist:jti:"+jti, "1", time.Minute).Err())
		r, err = s.Revoked(ctx, jti, sid)
		must(t, err)
		if !r {
			t.Fatal("JTI revocation missed")
		}
		must(t, client.Del(ctx, "denylist:jti:"+jti).Err())
		must(t, client.Set(ctx, "denylist:sid:"+sid, "1", time.Minute).Err())
		r, err = s.Revoked(ctx, jti, sid)
		must(t, err)
		if !r {
			t.Fatal("SID revocation missed")
		}
		must(t, client.Del(ctx, "denylist:sid:"+sid).Err())
	})
	t.Run("Redis atomic admission", func(t *testing.T) {
		k := "identity:f02:test:" + uuid.NewString()
		defer func() { _ = client.Del(ctx, k).Err() }()
		for i := 0; i < 3; i++ {
			ok, err := s.Admit(ctx, k, 2, time.Second)
			must(t, err)
			if ok != (i < 2) {
				t.Fatal("bad limit")
			}
		}
		ttl, err := client.PTTL(ctx, k).Result()
		must(t, err)
		if ttl <= 0 || ttl > time.Second {
			t.Fatal("fixed window TTL not anchored")
		}
	})
	m := manager(t)
	tok, err := m.IssueAccessV1(1, "user", "", time.Minute, 0, 0, "missing", "default", []string{"chat:read"})
	must(t, err)
	c, err := m.VerifyAccessV1(tok, jwt.JakeAudience)
	must(t, err)
	a := &identity.Authority{DB: db, Store: s}
	h := &identity.Handler{JWT: m, Authority: a, Keys: identity.ServiceKeys{CurrentID: "state", CurrentSecret: key("state")}}
	t.Run("missing durable state 401", func(t *testing.T) {
		w := request(t, h, tok, "default", h.Keys.CurrentSecret, "state", true)
		if w.Code != 401 {
			t.Fatalf("status %d", w.Code)
		}
	})
	t.Run("Redis actual adapter outage 503", func(t *testing.T) {
		broken := redis.NewClient(opts)
		must(t, broken.Close())
		bs := store.NewRedisStore(broken)
		if _, err := bs.Revoked(ctx, "j", "s"); err == nil {
			t.Fatal("outage became absence")
		}
		if _, err := bs.Admit(ctx, "k", 1, time.Second); err == nil {
			t.Fatal("outage admitted")
		}
		bh := *h
		bh.Authority = &identity.Authority{DB: db, Store: bs}
		if w := request(t, &bh, tok, "default", h.Keys.CurrentSecret, "state", true); w.Code != 503 {
			t.Fatalf("status %d", w.Code)
		}
	})
	t.Run("MySQL actual adapter outage 503", func(t *testing.T) {
		must(t, conn.Close())
		if err := a.Check(ctx, c); err == nil || errors.Is(err, identity.ErrInactive) {
			t.Fatal("DB failure became inactive/non-revoked")
		}
		if w := request(t, h, tok, "default", h.Keys.CurrentSecret, "state", true); w.Code != 503 {
			t.Fatalf("status %d", w.Code)
		}
	})
	t.Logf("real migrated MySQL v%d schema=%s and real Redis; state/tenant/fault/admission matrix passed", v, schema)
}
