package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/p5yheimu/dify-plugin-sso/internal/models"
)

// MockProviderService モックプロバイダーサービス
type MockProviderService struct {
	mock.Mock
}

func (m *MockProviderService) CreateProvider(name, providerType string, config map[string]interface{}) (*models.Provider, error) {
	args := m.Called(name, providerType, config)
	return args.Get(0).(*models.Provider), args.Error(1)
}

func (m *MockProviderService) GetProvider(providerID uuid.UUID) (*models.Provider, error) {
	args := m.Called(providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Provider), args.Error(1)
}

func (m *MockProviderService) ListProviders(providerType string) ([]*models.Provider, error) {
	args := m.Called(providerType)
	return args.Get(0).([]*models.Provider), args.Error(1)
}

func (m *MockProviderService) UpdateProvider(providerID uuid.UUID, name *string, config map[string]interface{}) (*models.Provider, error) {
	args := m.Called(providerID, name, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Provider), args.Error(1)
}

func (m *MockProviderService) DeleteProvider(providerID uuid.UUID) (bool, error) {
	args := m.Called(providerID)
	return args.Bool(0), args.Error(1)
}

func TestCreateProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewProviderHandler(mockService)

	// 正常なリクエスト
	providerReq := ProviderCreateRequest{
		Name: "Test SAML Provider",
		Type: "saml",
		Config: map[string]interface{}{
			"entity_id": "test",
			"idp_url":   "https://example.com/sso",
			"x509_cert": "test-cert",
		},
	}

	expectedProvider := &models.Provider{
		ID:     uuid.New(),
		Name:   providerReq.Name,
		Type:   providerReq.Type,
		Config: providerReq.Config,
	}

	mockService.On("CreateProvider", providerReq.Name, providerReq.Type, providerReq.Config).Return(expectedProvider, nil)

	// リクエスト作成
	reqBody, _ := json.Marshal(providerReq)
	req, _ := http.NewRequest("POST", "/api/v1/providers", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/api/v1/providers", handler.CreateProvider)
	router.ServeHTTP(w, req)

	// アサーション
	assert.Equal(t, http.StatusCreated, w.Code)
	
	var response models.Provider
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedProvider.Name, response.Name)
	assert.Equal(t, expectedProvider.Type, response.Type)

	mockService.AssertExpectations(t)
}

func TestListProviders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewProviderHandler(mockService)

	expectedProviders := []*models.Provider{
		{
			ID:   uuid.New(),
			Name: "Provider 1",
			Type: "saml",
		},
		{
			ID:   uuid.New(),
			Name: "Provider 2",
			Type: "oauth",
		},
	}

	mockService.On("ListProviders", "").Return(expectedProviders, nil)

	req, _ := http.NewRequest("GET", "/api/v1/providers", nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/providers", handler.ListProviders)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response []*models.Provider
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 2)

	mockService.AssertExpectations(t)
}

func TestGetProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewProviderHandler(mockService)

	providerID := uuid.New()
	expectedProvider := &models.Provider{
		ID:   providerID,
		Name: "Test Provider",
		Type: "saml",
	}

	mockService.On("GetProvider", providerID).Return(expectedProvider, nil)

	req, _ := http.NewRequest("GET", "/api/v1/providers/"+providerID.String(), nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/providers/:id", handler.GetProvider)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response models.Provider
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedProvider.ID, response.ID)
	assert.Equal(t, expectedProvider.Name, response.Name)

	mockService.AssertExpectations(t)
}

func TestGetProviderNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewProviderHandler(mockService)

	providerID := uuid.New()
	mockService.On("GetProvider", providerID).Return(nil, nil)

	req, _ := http.NewRequest("GET", "/api/v1/providers/"+providerID.String(), nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/providers/:id", handler.GetProvider)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	mockService.AssertExpectations(t)
} 