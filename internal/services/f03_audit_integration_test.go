//go:build integration

package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/identity"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/finnapigo/finnapigo/migrations"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func f03Keys(t *testing.T) *audit.Keys {
	t.Helper()
	key := func(s string) string {
		b := sha256.Sum256([]byte("F03 public synthetic fixture " + s))
		return base64.StdEncoding.EncodeToString(b[:])
	}
	k, err := audit.NewKeys("f03", map[string]string{"f03": key("audit")}, key("checkpoint"))
	mutationMust(t, err)
	return k
}

func f03DB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	if os.Getenv("F03_MYSQL_ALLOW_CREATE_DROP") != "1" || os.Getenv("F03_MYSQL_ADMIN_DSN") == "" {
		t.Fatal("BLOCKED: explicit isolated loopback F03 MySQL required")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("F03_MYSQL_ADMIN_DSN"))
	mutationMust(t, err)
	host, _, err := net.SplitHostPort(cfg.Addr)
	mutationMust(t, err)
	if cfg.Net != "tcp" || (host != "127.0.0.1" && host != "::1") || cfg.DBName != "" {
		t.Fatal("isolated loopback admin without application schema required")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	mutationMust(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	schema := "finnapigo_f03_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4")
	mutationMust(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP DATABASE `" + schema + "`"); mutationMust(t, err) })
	cfg.DBName = schema
	dsn := cfg.FormatDSN()
	mutationMust(t, database.RunMigrations(dsn))
	v, dirty, err := database.MigrationsVersion(dsn)
	mutationMust(t, err)
	if v != 6 || dirty {
		t.Fatal("migration state", v, dirty)
	}
	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{Logger: logger.Discard})
	mutationMust(t, err)
	pool, err := db.DB()
	mutationMust(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	return db, dsn
}

func f03Redis(t *testing.T) *store.RedisStore {
	t.Helper()
	opts, err := redis.ParseURL(os.Getenv("TEST_REDIS_URL"))
	mutationMust(t, err)
	host, _, err := net.SplitHostPort(opts.Addr)
	mutationMust(t, err)
	if host != "127.0.0.1" && host != "::1" {
		t.Fatal("loopback Redis required")
	}
	opts.DB = 13
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	mutationMust(t, client.Ping(context.Background()).Err())
	return store.NewRedisStore(client)
}

func f03Auth(t *testing.T, db *gorm.DB, kv *store.RedisStore, w *AsyncAuditWriter) (*AuthService, *TOTPService) {
	t.Helper()
	key := sha256.Sum256([]byte("F03 separate synthetic JWT"))
	mgr, err := jwt.NewConfiguredJWTManager(jwt.KeyConfig{Algorithm: "HS256", CurrentID: "f03-jwt", CurrentSecret: base64.StdEncoding.EncodeToString(key[:])})
	mutationMust(t, err)
	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	sessions := repositories.NewSessionRepository(db)
	rbac := repositories.NewRBACRepository(db)
	totps := repositories.NewTOTPRepository(db)
	authority := &identity.Authority{DB: db, Store: kv}
	mfa := NewTOTPService(totps, kv, w, "F03", config.AuthConfig{RecoveryCodeCount: 3, RecoveryCodeBytes: 16}, testEncryptor(t), mgr, WithTOTPUserRepo(users))
	svc := NewAuthService(users, tokens, repositories.NewUsedTokenRepository(db), w, kv, mgr, config.AuthConfig{BcryptCost: hash.MinCost}, config.RateLimitConfig{}, config.JWTConfig{AccessTTL: time.Minute, RefreshTTL: time.Hour, MFAPendingTTL: 5 * time.Minute}, &mockNotifier{}, nil, nil, totps, mfa, WithSessionRepo(sessions), WithAuthPermissions(rbac), WithAccessRevoker(authority), WithAccessState(func(ctx context.Context, c *jwt.Claims) error {
		if err := authority.Check(ctx, c); errors.Is(err, identity.ErrInactive) {
			return ErrInvalidCredentials
		} else {
			return err
		}
	}))
	return svc, mfa
}

func f03Drain(t *testing.T, r *repositories.AuditRepository) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, err := r.Dispatch(context.Background(), 1000)
		mutationMust(t, err)
		b, err := r.Backlog(context.Background())
		mutationMust(t, err)
		if b.Pending == 0 && b.Dead == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("durable delivery did not finish")
}

func TestF03RealProductionServiceTransactions(t *testing.T) {
	db, _ := f03DB(t)
	kv := f03Redis(t)
	keys := f03Keys(t)
	r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(keys))
	w := NewAsyncAuditWriter(r, r, config.AuditConfig{BufferSize: 1, FlushBatch: 64})
	t.Cleanup(w.Close)
	svc, mfa := f03Auth(t, db, kv, w)
	users := repositories.NewUserRepository(db)
	admin := NewAdminService(users, repositories.NewSessionRepository(db), repositories.NewRefreshTokenRepository(db), w, kv)
	devices := NewTrustedDeviceService(repositories.NewTrustedDeviceRepository(db), w)
	password := "F03SyntheticPassword42!"
	hashed, err := hash.HashPassword(password, hash.MinCost)
	mutationMust(t, err)
	for _, tid := range []string{"a", "b", "default"} {
		t.Run(tid, func(t *testing.T) {
			mutationMust(t, db.Where("id = ?", tid).FirstOrCreate(&models.Tenant{ID: tid, Slug: tid, Name: tid, IsActive: true}).Error)
			rid := uuid.NewString()
			ctx := audit.WithCorrelation(tenant.WithTenant(context.Background(), tid), rid)
			id := uuid.NewString()
			u := &models.User{TenantID: tid, Username: id, Email: id + "@example.invalid", Password: hashed, IsActive: true, IsEmailVerified: true}
			mutationMust(t, users.Create(ctx, u))
			deviceToken, _, err := devices.Issue(audit.WithActor(ctx, u.ID), u.ID, "synthetic", "127.0.0.1")
			mutationMust(t, err)
			valid, err := devices.Validate(ctx, u.ID, deviceToken)
			mutationMust(t, err)
			if !valid {
				t.Fatal("trusted device wiring")
			}
			pair, _, pending, err := svc.Login(ctx, LoginInput{Email: u.Email, Password: password}, "127.0.0.1", "synthetic")
			mutationMust(t, err)
			if pending != nil || pair.AccessToken == "" {
				t.Fatal("login issuance")
			}
			rotated, err := svc.Refresh(ctx, pair.RefreshToken, "127.0.0.1", "synthetic")
			mutationMust(t, err)
			adminID := u.ID + 100000
			mutationMust(t, admin.LockUser(ctx, adminID, u.ID, time.Hour, "127.0.0.1"))
			mutationMust(t, admin.UnlockUser(ctx, adminID, u.ID, "127.0.0.1"))
			secret, _, err := mfa.Enable(audit.WithActor(ctx, u.ID), u.ID, u.Email, "")
			mutationMust(t, err)
			code, err := totp.GenerateCode(secret, time.Now())
			mutationMust(t, err)
			codes, err := mfa.VerifyEnable(ctx, u.ID, code)
			mutationMust(t, err)
			_, _, pending, err = svc.Login(ctx, LoginInput{Email: u.Email, Password: password}, "127.0.0.1", "synthetic")
			mutationMust(t, err)
			if pending == nil {
				t.Fatal("MFA not wired")
			}
			_, _, err = svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: u.ID, Code: codes[0], IP: "127.0.0.1", UA: "synthetic"})
			mutationMust(t, err)
			f03Drain(t, r)
			rows, err := r.StreamAll(ctx, tid)
			mutationMust(t, err)
			events := map[string]bool{}
			for _, e := range rows {
				if e.TenantID != tid || e.RequestID != rid || e.RecordHash == "" || e.ActorKind != "authenticated" || e.ActorID == 0 || e.Email != "" || e.IPAddress != "" || e.Detail != "" {
					t.Fatalf("trusted capture/PII invariant: event=%s actor=%s", e.Event, e.ActorKind)
				}
				events[e.Event] = true
			}
			for _, event := range []string{"login", "refresh_token", "admin_action", "totp_staged", "totp_enabled", "mfa_pending", "recovery_code_used"} {
				if !events[event] {
					t.Fatal("missing wired event", event)
				}
			}
			if ok, err := r.VerifyChain(ctx, tid); !ok || err != nil {
				t.Fatal("integrity", ok, err)
			}
			// Trigger failure at the ACTUAL outbox INSERT. Every service must fail,
			// leave no newly issued secret, and roll back its SQL mutation.
			mutationMust(t, db.Exec("CREATE TRIGGER f03_reject BEFORE INSERT ON audit_outboxes FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='F03 synthetic admission outage'").Error)
			defer func() { mutationMust(t, db.Exec("DROP TRIGGER IF EXISTS f03_reject").Error) }()
			var before int64
			mutationMust(t, db.Model(&models.Session{}).Where("user_id = ?", u.ID).Count(&before).Error)
			badPair, _, err := svc.IssuePasskeyTokenPair(ctx, u, "127.0.0.1", "synthetic")
			if !errors.Is(err, audit.ErrUnavailable) || badPair.AccessToken != "" {
				t.Fatal("issuance acknowledged failed admission", err)
			}
			var after int64
			mutationMust(t, db.Model(&models.Session{}).Where("user_id = ?", u.ID).Count(&after).Error)
			if before != after {
				t.Fatal("session escaped rollback")
			}
			if err := admin.LockUser(ctx, adminID, u.ID, time.Hour, "127.0.0.1"); !errors.Is(err, audit.ErrUnavailable) {
				t.Fatal("admin returned success", err)
			}
			got, err := users.FindByID(ctx, u.ID)
			mutationMust(t, err)
			if got.LockedUntil != nil {
				t.Fatal("admin mutation escaped transaction")
			}
			failedDevice, _, err := devices.Issue(ctx, u.ID, "synthetic", "127.0.0.1")
			if !errors.Is(err, audit.ErrUnavailable) || failedDevice != "" {
				t.Fatal("device issuance bypassed durable admission", err)
			}
			refreshed, err := svc.Refresh(ctx, rotated.RefreshToken, "127.0.0.1", "synthetic")
			if !errors.Is(err, audit.ErrUnavailable) || refreshed.AccessToken != "" {
				t.Fatal("refresh returned success", err)
			}
			oldToken, err := repositories.NewRefreshTokenRepository(db).FindByHash(ctx, hash.HashToken(rotated.RefreshToken))
			mutationMust(t, err)
			if oldToken == nil || oldToken.Revoked {
				t.Fatal("refresh CAS escaped rollback")
			}
			oldPwd := got.Password
			oldVersion := got.PwdVersion
			if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: password, NewPassword: "F03NewSyntheticPassword42!"}, "127.0.0.1"); !errors.Is(err, audit.ErrUnavailable) {
				t.Fatal("credential returned success", err)
			}
			got, err = users.FindByID(ctx, u.ID)
			mutationMust(t, err)
			if got.Password != oldPwd || got.PwdVersion != oldVersion {
				t.Fatal("credential mutation escaped transaction")
			}
			// New recovery-code SQL consumption rolls back, while Redis challenges
			// already consumed may remain consumed; retry must use a fresh challenge.
			if err := mfa.Validate(ctx, u.ID, codes[1]); !errors.Is(err, audit.ErrUnavailable) {
				t.Fatal("MFA returned success", err)
			}
			var used models.RecoveryCode
			mutationMust(t, db.Where("code_hash = ?", hash.HashToken(codes[1])).First(&used).Error)
			if used.UsedAt != nil {
				t.Fatal("MFA consumption escaped transaction")
			}
			mutationMust(t, db.Exec("DROP TRIGGER f03_reject").Error)
			_, err = svc.Refresh(ctx, rotated.RefreshToken, "127.0.0.1", "synthetic")
			mutationMust(t, err)
		})
	}
	f03Drain(t, r)
	// The synthetic retention rehearsal uses events emitted by the real async
	// login/refresh/admin/MFA services above. It is NOT production policy.
	ctx := tenant.WithTenant(context.Background(), "a")
	base := keys.Checkpoint("a", 0, repositories.GenesisAuditHash)
	end, err := r.Checkpoint(ctx)
	mutationMust(t, err)
	p := repositories.RetentionPolicy{Approval: "SYNTHETIC F03 TEST ONLY", Enabled: true, Before: time.Now().Add(time.Hour), MaxRows: 1000}
	archive, err := r.Archive(ctx, p, base)
	mutationMust(t, err)
	mutationMust(t, r.PurgeArchive(ctx, p, archive, end))
	mutationMust(t, db.Exec("CREATE TRIGGER f03_restore_fail BEFORE INSERT ON audit_logs FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='F03 synthetic restore outage'").Error)
	if r.RestoreArchive(ctx, archive, end) == nil {
		t.Fatal("restore outage hidden")
	}
	if ok, err := r.VerifyChain(ctx, "a"); !ok || err != nil {
		t.Fatal("failed restore changed boundary", ok, err)
	}
	mutationMust(t, db.Exec("DROP TRIGGER f03_restore_fail").Error)
	mutationMust(t, r.RestoreArchive(ctx, archive, end))
	mutationMust(t, r.VerifyAgainst(ctx, base, end))
	last := archive.Events[len(archive.Events)-1]
	mutationMust(t, db.Where("event_id = ?", last.EventID).Delete(&models.AuditLog{}).Error)
	if r.VerifyAgainst(ctx, base, end) == nil {
		t.Fatal("independently anchored tail truncation accepted")
	}
	mutationMust(t, db.Create(&last).Error)
	mutationMust(t, r.ValidateKeyHistory(ctx))
	w.Close()
	w.Close()
	t.Log("real migrated MySQL + Redis: tenants A/B/default login/refresh/admin/MFA; trigger faults roll back issuance/session/refresh/credential/factor SQL")
}

func TestF03MigrationLegacyUpDown(t *testing.T) {
	db, dsn := f03DB(t)
	src, err := iofs.New(migrations.FS, ".")
	mutationMust(t, err)
	m, err := migrate.NewWithSourceInstance("iofs", src, "mysql://"+dsn)
	mutationMust(t, err)
	defer func() { _, _ = m.Close() }()
	mutationMust(t, m.Steps(-1))
	mutationMust(t, db.Exec("INSERT INTO audit_logs(tenant_id,event,email,record_hash) VALUES ('default','legacy','synthetic@example.invalid','untrusted-old-signature')").Error)
	mutationMust(t, m.Up())
	var legacy models.AuditLog
	mutationMust(t, db.Where("event = ?", "legacy").First(&legacy).Error)
	if legacy.Version != 0 || legacy.Sequence != nil || legacy.EventID != "" || legacy.RecordHash != "untrusted-old-signature" {
		t.Fatal("migration invented history")
	}
	r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(f03Keys(t)))
	if ok, err := r.VerifyChain(context.Background(), "default"); ok || !errors.Is(err, audit.ErrLegacy) {
		t.Fatal("legacy treated as verified", ok, err)
	}
	mutationMust(t, m.Down())
	mutationMust(t, m.Up())
	v, dirty, err := m.Version()
	mutationMust(t, err)
	if v != 6 || dirty {
		t.Fatal("migration replay", v, dirty)
	}
	t.Log("real MySQL 0005 legacy fixture -> 0006 preserves v0/unverifiable; all migrations DOWN/UP clean")
}

func TestF03ReplicaReplayAndProcessTermination(t *testing.T) {
	if os.Getenv("F03_CHILD_DSN") != "" {
		cfg, err := mysql.ParseDSN(os.Getenv("F03_CHILD_DSN"))
		if err != nil {
			os.Exit(24)
		}
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err != nil || cfg.Net != "tcp" || host != "127.0.0.1" || !strings.HasPrefix(cfg.DBName, "finnapigo_f03_") || os.Getenv("F03_MYSQL_ALLOW_CREATE_DROP") != "1" {
			os.Exit(24)
		}
		db, err := gorm.Open(gormmysql.Open(os.Getenv("F03_CHILD_DSN")), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			os.Exit(24)
		}
		r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(f03Keys(t)))
		if err := r.Admit(tenant.WithTenant(context.Background(), "crash"), &models.AuditLog{Event: "process_admitted", Success: true}); err != nil {
			os.Exit(25)
		}
		os.Exit(23) // no defer/shutdown/queue flush; committed copy must survive
	}
	db, dsn := f03DB(t)
	r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(f03Keys(t)))
	child := exec.Command(os.Args[0], "-test.run=^TestF03ReplicaReplayAndProcessTermination$")
	child.Env = append(os.Environ(), "F03_CHILD_DSN="+dsn)
	err := child.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatal("termination harness", err)
	}
	var admitted int64
	mutationMust(t, db.Model(&models.AuditOutbox{}).Where("tenant_id = ? AND state = ?", "crash", "pending").Count(&admitted).Error)
	if admitted != 1 {
		t.Fatal("committed outbox lost after process exit")
	}
	// Separate pools emulate replicas, with concurrent admission AND dispatch.
	var wg sync.WaitGroup
	fail := make(chan error, 32)
	for replica := range 4 {
		wg.Go(func() {
			other, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				fail <- err
				return
			}
			pool, _ := other.DB()
			defer func() { _ = pool.Close() }()
			repo := repositories.NewAuditRepository(other, repositories.WithAuditKeys(f03Keys(t)))
			for i := range 20 {
				tid := []string{"a", "b", "default"}[(i+replica)%3]
				ctx, cancel := context.WithCancel(audit.WithActor(tenant.WithTenant(context.Background(), tid), 42))
				err := repo.Admit(ctx, &models.AuditLog{Event: "replica_batch", Success: true})
				cancel()
				if err != nil {
					fail <- err
					return
				}
				if _, err := repo.Dispatch(context.Background(), 3); err != nil {
					fail <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		mutationMust(t, err)
	}
	f03Drain(t, r)
	ctx := tenant.WithTenant(context.Background(), "crash")
	mutationMust(t, r.Admit(ctx, &models.AuditLog{Event: "lease_recovered", Success: true}))
	old, err := r.Claim(ctx, time.Now())
	mutationMust(t, err)
	mutationMust(t, db.Model(old).Update("lease_until", time.Now().UTC().Add(-time.Minute)).Error)
	fresh, err := r.Claim(ctx, time.Now())
	mutationMust(t, err)
	if old == nil || fresh == nil || old.LeaseToken == fresh.LeaseToken || r.Deliver(ctx, old) == nil {
		t.Fatal("stale real worker was not fenced")
	}
	mutationMust(t, r.Deliver(ctx, fresh))
	mutationMust(t, r.Deliver(ctx, old))
	var total int64
	mutationMust(t, db.Model(&models.AuditLog{}).Count(&total).Error)
	if total != 82 {
		t.Fatal("duplicate/lost events", total)
	}
	for _, tid := range []string{"a", "b", "default", "crash"} {
		ctx := tenant.WithTenant(context.Background(), tid)
		if ok, err := r.VerifyChain(ctx, tid); !ok || err != nil {
			t.Fatal(tid, ok, err)
		}
	}
	t.Log("4 independent MySQL pools, 80 concurrent admissions + delivery, abrupt process exit and stale/reclaimed/duplicate worker: 82 unique events; zero observed forks/duplicates/loss")
}

type f03AdmissionNotifier struct {
	mockNotifier
	before func() error
	sent   int
}

func (n *f03AdmissionNotifier) SendPasswordReset(context.Context, string, string) error {
	if err := n.before(); err != nil {
		return err
	}
	n.sent++
	return nil
}
func TestF03RecoveryAdmissionPrecedesExternalIssuance(t *testing.T) {
	db, _ := f03DB(t)
	kv := f03Redis(t)
	r := repositories.NewAuditRepository(db, repositories.WithAuditKeys(f03Keys(t)))
	w := NewAsyncAuditWriter(r, r, config.AuditConfig{BufferSize: 1, FlushBatch: 64})
	defer w.Close()
	svc, _ := f03Auth(t, db, kv, w)
	u := &models.User{TenantID: "default", Username: uuid.NewString(), Email: uuid.NewString() + "@example.invalid", IsActive: true}
	mutationMust(t, repositories.NewUserRepository(db).Create(context.Background(), u))
	notifier := &f03AdmissionNotifier{before: func() error {
		// This query uses a separate pool connection, with no operation context;
		// it cannot observe an uncommitted INSERT from the request transaction.
		var n int64
		if err := db.Model(&models.AuditOutbox{}).Where("tenant_id = ? AND sequence > 0", "default").Count(&n).Error; err != nil {
			return err
		}
		if n < 1 {
			return errors.New("credential left before committed audit")
		}
		return nil
	}}
	svc.notify = notifier
	mutationMust(t, svc.ForgotPassword(context.Background(), u.Email, "127.0.0.1"))
	if notifier.sent != 1 {
		t.Fatal("recovery notifier was not invoked")
	}
	mutationMust(t, db.Exec("CREATE TRIGGER f03_email_reject BEFORE INSERT ON audit_outboxes FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='F03 synthetic admission outage'").Error)
	defer func() { mutationMust(t, db.Exec("DROP TRIGGER IF EXISTS f03_email_reject").Error) }()
	if err := svc.ForgotPassword(context.Background(), u.Email, "127.0.0.1"); !errors.Is(err, audit.ErrUnavailable) || notifier.sent != 1 {
		t.Fatal("external credential issuance bypassed failed admission", err)
	}
	t.Log("password-recovery evidence observed committed on independent SQL connection before notifier; admission failure emitted no credential")
}
