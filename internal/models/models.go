package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Provider SSOプロバイダー情報
type Provider struct {
	ID        uuid.UUID              `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name      string                 `gorm:"not null;size:255" json:"name"`
	Type      string                 `gorm:"not null;size:50" json:"type"` // 'saml', 'oauth', 'oidc'
	Config    map[string]interface{} `gorm:"type:jsonb" json:"config"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// Session SSOセッション情報
type Session struct {
	ID          uuid.UUID              `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      string                 `gorm:"not null;size:255" json:"user_id"`
	ProviderID  uuid.UUID              `gorm:"type:uuid;not null" json:"provider_id"`
	Provider    Provider               `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
	SessionData map[string]interface{} `gorm:"type:jsonb" json:"session_data"`
	ExpiresAt   time.Time              `gorm:"not null" json:"expires_at"`
	CreatedAt   time.Time              `json:"created_at"`
}

// AuditLog 監査ログ
type AuditLog struct {
	ID         uuid.UUID              `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EventType  string                 `gorm:"not null;size:100" json:"event_type"`
	UserID     *string                `gorm:"size:255" json:"user_id,omitempty"`
	ProviderID *uuid.UUID             `gorm:"type:uuid" json:"provider_id,omitempty"`
	Provider   *Provider              `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
	IPAddress  *string                `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent  *string                `json:"user_agent,omitempty"`
	EventData  map[string]interface{} `gorm:"type:jsonb" json:"event_data"`
	Timestamp  time.Time              `gorm:"default:now()" json:"timestamp"`
}

// BeforeCreate UUIDを自動生成
func (p *Provider) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

// TableName テーブル名を明示的に指定
func (Provider) TableName() string {
	return "dify_sso_providers"
}

func (Session) TableName() string {
	return "dify_sso_sessions"
}

func (AuditLog) TableName() string {
	return "dify_sso_audit_logs"
} 