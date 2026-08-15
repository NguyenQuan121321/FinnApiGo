package models

import "time"

// OTP purpose constants.
const (
	OTPPurposeLogin         = "login"
	OTPPurposeVerifyEmail   = "verify-email"
	OTPPurposeResetPassword = "reset-password"
)

// OtpCode stores a hashed one-time password for MFA / email verification /
// password reset flows. Only the hash is stored; the plaintext is delivered
// to the user out-of-band (email/SMS).
type OtpCode struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       uint      `gorm:"index;not null" json:"userId"`
	CodeHash     string    `gorm:"size:64;not null" json:"-"` // sha256 hex
	Purpose      string    `gorm:"size:30;not null" json:"purpose"`
	ExpiresAt    time.Time `gorm:"not null" json:"expiresAt"`
	IsUsed       bool      `gorm:"not null;default:false" json:"isUsed"`
	AttemptCount int       `gorm:"not null;default:0" json:"attemptCount"`
	CreatedAt    time.Time `json:"createdAt"`
}

func (OtpCode) TableName() string { return "otp_codes" }
