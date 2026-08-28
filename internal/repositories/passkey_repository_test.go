package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
)

func passkeyUser(t *testing.T, db *gorm.DB, username string) *models.User {
	t.Helper()
	u := &models.User{Username: username, Email: username + "@example.com", Password: "hash", Role: models.RoleUser, IsActive: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPasskeyRepository_CRUD_W1(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	repo := NewPasskeyRepository(db)
	u := passkeyUser(t, db, "pkuser")

	pc := &models.PasskeyCredential{
		UserID:          u.ID,
		CredentialID:    []byte("cred-0001"),
		PublicKey:       []byte{0x01, 0x02, 0x03},
		SignCount:       5,
		DisplayName:     "MacBook Touch ID",
		Transports:      `["internal","hybrid"]`,
		AttestationType: "none",
	}
	if err := repo.Create(ctx, pc); err != nil {
		t.Fatal(err)
	}
	if pc.ID == 0 {
		t.Fatal("created credential must have an id")
	}

	// Lookup by credential ID (the WebAuthn authentication path).
	got, err := repo.FindByCredentialID(ctx, []byte("cred-0001"))
	if err != nil || got == nil {
		t.Fatalf("FindByCredentialID=%+v err=%v", got, err)
	}
	if got.UserID != u.ID || got.SignCount != 5 || got.DisplayName != "MacBook Touch ID" {
		t.Fatalf("row mismatch: %+v", got)
	}

	// credential_id is globally unique — registering the same authenticator
	// twice (even under another user) must be rejected.
	other := passkeyUser(t, db, "pkuser2")
	dup := &models.PasskeyCredential{UserID: other.ID, CredentialID: []byte("cred-0001"), PublicKey: []byte{0x09}}
	if err := repo.Create(ctx, dup); err == nil {
		t.Fatal("duplicate credential_id must be rejected")
	}

	if missing, err := repo.FindByCredentialID(ctx, []byte("no-such-cred")); err != nil || missing != nil {
		t.Fatalf("missing credential: got=%+v err=%v", missing, err)
	}
}

func TestPasskeyRepository_ListAndUsage_W6(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	repo := NewPasskeyRepository(db)
	u := passkeyUser(t, db, "pklist")
	attacker := passkeyUser(t, db, "pkattacker")

	mk := func(name, credID string) *models.PasskeyCredential {
		pc := &models.PasskeyCredential{UserID: u.ID, CredentialID: []byte(credID), PublicKey: []byte{1}, DisplayName: name}
		if err := repo.Create(ctx, pc); err != nil {
			t.Fatal(err)
		}
		return pc
	}
	phone := mk("iPhone Face ID", "cred-a")
	laptop := mk("YubiKey 5", "cred-b")

	rows, err := repo.ListByUser(ctx, u.ID, false)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListByUser=%d err=%v", len(rows), err)
	}

	// Usage maintenance: sign counter + last_used_at.
	now := time.Now()
	if err := repo.TouchUsage(ctx, phone.ID, 42, now); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.FindByCredentialID(ctx, []byte("cred-a"))
	if got.SignCount != 42 || got.LastUsedAt == nil {
		t.Fatalf("TouchUsage not persisted: %+v", got)
	}

	// Revoke one — CAS scoped to the owner; it disappears from the default
	// device list but stays retrievable for clone forensics.
	if err := repo.RevokeByID(ctx, laptop.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	rows, _ = repo.ListByUser(ctx, u.ID, false)
	if len(rows) != 1 || rows[0].DisplayName != "iPhone Face ID" {
		t.Fatalf("revoked credential must leave the device list: %+v", rows)
	}
	rows, _ = repo.ListByUser(ctx, u.ID, true)
	if len(rows) != 2 {
		t.Fatalf("includeRevoked must return both rows: %d", len(rows))
	}
	if err := repo.RevokeByID(ctx, laptop.ID, u.ID); err == nil {
		t.Fatal("double revoke must fail (CAS)")
	}
	if err := repo.RevokeByID(ctx, phone.ID, attacker.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatal("revoking another user's credential must fail (IDOR scope)")
	}
}
