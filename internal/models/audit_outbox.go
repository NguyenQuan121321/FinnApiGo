package models

import "time"

type AuditHead struct {
	TenantID string `gorm:"primaryKey;size:36"`
	Sequence uint64 `gorm:"not null"`
	Hash     string `gorm:"size:64;not null"`
	Pending  int    `gorm:"not null"`
}

// Delivered payloads are cleared; the minimal event identity/hash receipt is
// retained for replay protection. Dead rows remain durable until operator replay.
type AuditOutbox struct {
	EventID     string    `gorm:"primaryKey;size:36"`
	TenantID    string    `gorm:"size:36;not null;uniqueIndex:ux_outbox_sequence,priority:1"`
	Sequence    uint64    `gorm:"not null;uniqueIndex:ux_outbox_sequence,priority:2"`
	Hash        string    `gorm:"size:64;not null"`
	KeyID       string    `gorm:"size:64;not null"`
	Payload     string    `gorm:"type:longtext;not null"`
	State       string    `gorm:"size:16;not null;index:idx_outbox_due,priority:1"`
	Attempts    int       `gorm:"not null"`
	AvailableAt time.Time `gorm:"index:idx_outbox_due,priority:2"`
	LeaseUntil  *time.Time
	LeaseToken  string `gorm:"size:36"`
	LastError   string `gorm:"size:32"` // fixed code; never raw driver/SQL/payload errors
	CreatedAt   time.Time
}

type AuditBoundary struct {
	TenantID string `gorm:"primaryKey;size:36"`
	Sequence uint64
	Hash     string `gorm:"size:64"`
}
