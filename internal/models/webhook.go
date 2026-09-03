package models

import "time"

// WebhookEndpoint represents a subscriber endpoint for event dispatch (P2.5).
type WebhookEndpoint struct {
	ID        string    `gorm:"primaryKey;size:36"                     json:"id"`
	TenantID  string    `gorm:"size:36;not null;default:default;index" json:"tenantId"`
	URL       string    `gorm:"size:500;not null"                      json:"url"`
	Secret    string    `gorm:"size:255;not null"                      json:"-"`
	Events    string    `gorm:"type:text;not null"                     json:"events"`
	IsActive  bool      `gorm:"not null;default:true"                  json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (WebhookEndpoint) TableName() string { return "webhook_endpoints" }

// WebhookDelivery records outbox dispatch attempts for a webhook event (P2.5).
type WebhookDelivery struct {
	ID             string     `gorm:"primaryKey;size:36"              json:"id"`
	EndpointID     string     `gorm:"size:36;not null;index"          json:"endpointId"`
	Event          string     `gorm:"size:50;not null"                json:"event"`
	Payload        string     `gorm:"type:text;not null"              json:"payload"`
	Status         string     `gorm:"size:20;not null;default:pending;index" json:"status"`
	Attempts       int        `gorm:"not null;default:0"              json:"attempts"`
	NextRetryAt    *time.Time `gorm:"index"                           json:"nextRetryAt"`
	ResponseStatus *int       `json:"responseStatus"`
	ErrorMsg       string     `gorm:"type:text"                       json:"errorMsg"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

func (WebhookDelivery) TableName() string { return "webhook_deliveries" }
