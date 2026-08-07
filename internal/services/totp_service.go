package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/pquerna/otp/totp"
	"time"
)

type TOTPService struct {
	repo   TOTPRepo
	store  StoreProvider
	issuer string
}

func NewTOTPService(repo TOTPRepo, store StoreProvider, issuer string) *TOTPService {
	return &TOTPService{repo: repo, store: store, issuer: issuer}
}
func (s *TOTPService) Enable(ctx context.Context, userID uint, email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer, AccountName: email})
	if err != nil {
		return "", "", fmt.Errorf("totp generate: %w", err)
	}
	d := &models.TOTPDevice{UserID: userID, Secret: key.Secret(), Enabled: false}
	if old, e := s.repo.FindByUserID(ctx, userID); e != nil {
		return "", "", e
	} else if old != nil {
		d.ID = old.ID
	}
	if err = s.repo.Upsert(ctx, d); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
func (s *TOTPService) VerifyEnable(ctx context.Context, userID uint, code string) ([]string, error) {
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil || d == nil {
		return nil, ErrInvalidOTP
	}
	if d.Enabled {
		return nil, ErrInvalidInput
	}
	if !totp.Validate(code, d.Secret) {
		return nil, ErrInvalidOTP
	}
	d.Enabled = true
	if err = s.repo.Upsert(ctx, d); err != nil {
		return nil, err
	}
	return s.newRecoveryCodes(ctx, userID)
}
func (s *TOTPService) Validate(ctx context.Context, userID uint, code string) error {
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if d == nil || !d.Enabled {
		return ErrInvalidOTP
	}
	if totp.Validate(code, d.Secret) {
		sum := sha256.Sum256([]byte(code))
		key := "totp:replay:" + fmt.Sprint(userID) + ":" + hex.EncodeToString(sum[:])
		if s.store != nil && !s.store.SetNX(key, "1", 30*time.Second) {
			return ErrInvalidOTP
		}
		return nil
	}
	codes, err := s.repo.ActiveRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}
	for i := range codes {
		if hash.CheckPassword(codes[i].CodeHash, code) {
			return s.repo.MarkRecoveryCodeUsed(ctx, &codes[i])
		}
	}
	return ErrInvalidOTP
}
func (s *TOTPService) newRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	plain := make([]string, 10)
	rows := make([]*models.RecoveryCode, 10)
	for i := range plain {
		b, err := hash.GenerateRandomBytes(8)
		if err != nil {
			return nil, err
		}
		plain[i] = hex.EncodeToString(b)
		h, err := hash.HashPassword(plain[i])
		if err != nil {
			return nil, err
		}
		rows[i] = &models.RecoveryCode{UserID: userID, CodeHash: h}
	}
	return plain, s.repo.CreateRecoveryCodes(ctx, rows)
}
