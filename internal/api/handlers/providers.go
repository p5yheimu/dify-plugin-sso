package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/p5yheimu/dify-plugin-sso/internal/service"
	"github.com/sirupsen/logrus"
)

// ProviderHandler プロバイダー管理APIハンドラー
type ProviderHandler struct {
	service *service.ProviderService
	logger  *logrus.Logger
}

// NewProviderHandler 新しいProviderHandlerを作成
func NewProviderHandler(service *service.ProviderService) *ProviderHandler {
	return &ProviderHandler{
		service: service,
		logger:  logrus.New(),
	}
}

// ProviderCreateRequest プロバイダー作成リクエスト
type ProviderCreateRequest struct {
	Name   string                 `json:"name" binding:"required,min=1,max=255"`
	Type   string                 `json:"type" binding:"required,oneof=saml oauth oidc"`
	Config map[string]interface{} `json:"config" binding:"required"`
}

// ProviderUpdateRequest プロバイダー更新リクエスト
type ProviderUpdateRequest struct {
	Name   *string                `json:"name,omitempty"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// CreateProvider 新しいSSOプロバイダーを作成
func (h *ProviderHandler) CreateProvider(c *gin.Context) {
	var req ProviderCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	provider, err := h.service.CreateProvider(req.Name, req.Type, req.Config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create provider")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, provider)
}

// ListProviders プロバイダー一覧を取得
func (h *ProviderHandler) ListProviders(c *gin.Context) {
	providerType := c.Query("type")

	providers, err := h.service.ListProviders(providerType)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list providers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, providers)
}

// GetProvider 特定のプロバイダーを取得
func (h *ProviderHandler) GetProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	provider, err := h.service.GetProvider(providerID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// UpdateProvider プロバイダーを更新
func (h *ProviderHandler) UpdateProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	var req ProviderUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedProvider, err := h.service.UpdateProvider(providerID, req.Name, req.Config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update provider")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if updatedProvider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, updatedProvider)
}

// DeleteProvider プロバイダーを削除
func (h *ProviderHandler) DeleteProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	success, err := h.service.DeleteProvider(providerID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !success {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider deleted successfully"})
}

// RegisterRoutes プロバイダー管理のルートを登録
func (h *ProviderHandler) RegisterRoutes(router *gin.RouterGroup) {
	providers := router.Group("/providers")
	{
		providers.POST("/", h.CreateProvider)
		providers.GET("/", h.ListProviders)
		providers.GET("/:id", h.GetProvider)
		providers.PUT("/:id", h.UpdateProvider)
		providers.DELETE("/:id", h.DeleteProvider)
	}
} 