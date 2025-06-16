package service

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/p5yheimu/dify-plugin-sso/internal/auth/saml"
	"github.com/p5yheimu/dify-plugin-sso/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// ProviderService SSOプロバイダー管理サービス
type ProviderService struct {
	db     *gorm.DB
	logger *logrus.Logger
}

// NewProviderService 新しいProviderServiceを作成
func NewProviderService(db *gorm.DB) *ProviderService {
	return &ProviderService{
		db:     db,
		logger: logrus.New(),
	}
}

// CreateProvider 新しいSSOプロバイダーを作成
func (s *ProviderService) CreateProvider(name, providerType string, config map[string]interface{}) (*models.Provider, error) {
	// 設定検証
	if !s.validateProviderConfig(providerType, config) {
		return nil, fmt.Errorf("invalid configuration for %s provider", providerType)
	}

	provider := &models.Provider{
		Name:   name,
		Type:   providerType,
		Config: config,
	}

	if err := s.db.Create(provider).Error; err != nil {
		s.logger.WithError(err).Error("Failed to create provider")
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"provider_id": provider.ID,
		"name":        name,
		"type":        providerType,
	}).Info("Provider created")

	return provider, nil
}

// GetProvider プロバイダーIDでプロバイダーを取得
func (s *ProviderService) GetProvider(providerID uuid.UUID) (*models.Provider, error) {
	var provider models.Provider
	if err := s.db.First(&provider, "id = ?", providerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}
	return &provider, nil
}

// ListProviders プロバイダー一覧を取得
func (s *ProviderService) ListProviders(providerType string) ([]*models.Provider, error) {
	var providers []*models.Provider
	query := s.db

	if providerType != "" {
		query = query.Where("type = ?", providerType)
	}

	if err := query.Find(&providers).Error; err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}

	return providers, nil
}

// UpdateProvider プロバイダーを更新
func (s *ProviderService) UpdateProvider(providerID uuid.UUID, name *string, config map[string]interface{}) (*models.Provider, error) {
	var provider models.Provider
	if err := s.db.First(&provider, "id = ?", providerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// 設定検証（設定が提供されている場合）
	if config != nil && !s.validateProviderConfig(provider.Type, config) {
		return nil, fmt.Errorf("invalid configuration for %s provider", provider.Type)
	}

	updates := map[string]interface{}{}
	if name != nil {
		updates["name"] = *name
	}
	if config != nil {
		updates["config"] = config
	}

	if err := s.db.Model(&provider).Updates(updates).Error; err != nil {
		s.logger.WithError(err).Error("Failed to update provider")
		return nil, fmt.Errorf("failed to update provider: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"provider_id": providerID,
		"name":        provider.Name,
	}).Info("Provider updated")

	return &provider, nil
}

// DeleteProvider プロバイダーを削除
func (s *ProviderService) DeleteProvider(providerID uuid.UUID) (bool, error) {
	var provider models.Provider
	if err := s.db.First(&provider, "id = ?", providerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get provider: %w", err)
	}

	if err := s.db.Delete(&provider).Error; err != nil {
		s.logger.WithError(err).Error("Failed to delete provider")
		return false, fmt.Errorf("failed to delete provider: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"provider_id": providerID,
		"name":        provider.Name,
	}).Info("Provider deleted")

	return true, nil
}

// GetSAMLAuthenticator SAMLプロバイダーのAuthenticatorを取得
func (s *ProviderService) GetSAMLAuthenticator(providerID uuid.UUID) (*saml.Authenticator, error) {
	provider, err := s.GetProvider(providerID)
	if err != nil {
		return nil, err
	}
	if provider == nil || provider.Type != "saml" {
		return nil, nil
	}

	// 設定をSAMLConfigに変換
	configBytes, err := json.Marshal(provider.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var samlConfig saml.Config
	if err := json.Unmarshal(configBytes, &samlConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SAML config: %w", err)
	}

	authenticator, err := saml.NewAuthenticator(&samlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML authenticator: %w", err)
	}

	return authenticator, nil
}

// validateProviderConfig プロバイダー設定を検証
func (s *ProviderService) validateProviderConfig(providerType string, config map[string]interface{}) bool {
	switch providerType {
	case "saml":
		requiredFields := []string{"idp_url", "entity_id", "x509_cert"}
		return s.hasRequiredFields(config, requiredFields)
	case "oauth":
		requiredFields := []string{"client_id", "client_secret", "authorization_url", "token_url"}
		return s.hasRequiredFields(config, requiredFields)
	case "oidc":
		requiredFields := []string{"client_id", "client_secret", "discovery_url"}
		return s.hasRequiredFields(config, requiredFields)
	default:
		return false
	}
}

// hasRequiredFields 必須フィールドが存在するかチェック
func (s *ProviderService) hasRequiredFields(config map[string]interface{}, requiredFields []string) bool {
	for _, field := range requiredFields {
		if _, exists := config[field]; !exists {
			return false
		}
	}
	return true
} 