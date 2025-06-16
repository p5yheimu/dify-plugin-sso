package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/p5yheimu/dify-plugin-sso/internal/models"
)

func TestGetMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewSAMLHandler(mockService)

	providerID := uuid.New()
	samlProvider := &models.Provider{
		ID:   providerID,
		Name: "Test SAML Provider",
		Type: "saml",
		Config: map[string]interface{}{
			"entity_id":     "test-entity",
			"idp_url":       "https://idp.example.com/sso",
			"idp_entity_id": "https://idp.example.com",
			"x509_cert":     "MIICertData",
			"sp_acs_url":    "https://sp.example.com/acs",
			"sp_sls_url":    "https://sp.example.com/sls",
		},
	}

	// GetProvider should return the SAML provider
	mockService.On("GetProvider", providerID).Return(samlProvider, nil)
	// GetSAMLAuthenticator should return nil to avoid actual SAML creation
	mockService.On("GetSAMLAuthenticator", providerID).Return(nil, nil)

	req, _ := http.NewRequest("GET", "/api/v1/saml/metadata/"+providerID.String(), nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/saml/metadata/:provider_id", handler.GetMetadata)
	router.ServeHTTP(w, req)

	// Should return 404 because we're returning nil authenticator
	assert.Equal(t, http.StatusNotFound, w.Code)

	mockService.AssertExpectations(t)
}

func TestGetMetadataProviderNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewSAMLHandler(mockService)

	providerID := uuid.New()
	mockService.On("GetSAMLAuthenticator", providerID).Return(nil, nil)

	req, _ := http.NewRequest("GET", "/api/v1/saml/metadata/"+providerID.String(), nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/saml/metadata/:provider_id", handler.GetMetadata)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	mockService.AssertExpectations(t)
}

func TestInitiateAuthProviderNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockProviderService)
	handler := NewSAMLHandler(mockService)

	providerID := uuid.New()
	mockService.On("GetSAMLAuthenticator", providerID).Return(nil, nil)

	req, _ := http.NewRequest("GET", "/api/v1/saml/auth/"+providerID.String(), nil)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/api/v1/saml/auth/:provider_id", handler.InitiateAuth)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	mockService.AssertExpectations(t)
} 