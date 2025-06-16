package service

import (
	"github.com/google/uuid"
	"github.com/p5yheimu/dify-plugin-sso/internal/auth/saml"
	"github.com/p5yheimu/dify-plugin-sso/internal/models"
)

// ProviderServiceInterface SSOプロバイダー管理サービスのインターフェース
type ProviderServiceInterface interface {
	// CRUD operations
	CreateProvider(name, providerType string, config map[string]interface{}) (*models.Provider, error)
	GetProvider(providerID uuid.UUID) (*models.Provider, error)
	ListProviders(providerType string) ([]*models.Provider, error)
	UpdateProvider(providerID uuid.UUID, name *string, config map[string]interface{}) (*models.Provider, error)
	DeleteProvider(providerID uuid.UUID) (bool, error)
	
	// SAML specific operations
	GetSAMLAuthenticator(providerID uuid.UUID) (*saml.Authenticator, error)
}

// Ensure ProviderService implements ProviderServiceInterface
var _ ProviderServiceInterface = (*ProviderService)(nil) 