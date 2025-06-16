package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/p5yheimu/dify-plugin-sso/internal/service"
	"github.com/sirupsen/logrus"
)

// SAMLHandler SAML認証APIハンドラー
type SAMLHandler struct {
	providerService *service.ProviderService
	logger          *logrus.Logger
}

// NewSAMLHandler 新しいSAMLHandlerを作成
func NewSAMLHandler(providerService *service.ProviderService) *SAMLHandler {
	return &SAMLHandler{
		providerService: providerService,
		logger:          logrus.New(),
	}
}

// InitiateAuth SAML認証を開始
func (h *SAMLHandler) InitiateAuth(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	// SAMLAuthenticatorを取得
	authenticator, err := h.providerService.GetSAMLAuthenticator(providerID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get SAML authenticator")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if authenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SAML provider not found"})
		return
	}

	// RelayState（リダイレクト先URL）を取得
	relayState := c.Query("relay_state")

	// 認証リクエストURLを生成
	authURL, err := authenticator.CreateAuthRequest("", relayState)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create auth request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create auth request"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"provider_id": providerID,
		"auth_url":    authURL,
	}).Info("SAML auth initiated")

	// リダイレクトまたはJSONレスポンス
	if c.Query("format") == "json" {
		c.JSON(http.StatusOK, gin.H{"auth_url": authURL})
	} else {
		c.Redirect(http.StatusFound, authURL)
	}
}

// HandleCallback SAML認証コールバック（ACS）を処理
func (h *SAMLHandler) HandleCallback(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	// SAMLAuthenticatorを取得
	authenticator, err := h.providerService.GetSAMLAuthenticator(providerID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get SAML authenticator")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if authenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SAML provider not found"})
		return
	}

	// SAMLレスポンスを検証
	userData, err := authenticator.ValidateResponse(c.Request)
	if err != nil {
		h.logger.WithError(err).Error("Failed to validate SAML response")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAML response"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"provider_id": providerID,
		"name_id":     userData.NameID,
	}).Info("SAML auth successful")

	// セッション作成（将来的にはSessionServiceで処理）
	// TODO: ここでユーザーセッションを作成し、Difyに通知

	// レスポンス
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"user_id":    userData.NameID,
		"attributes": userData.Attributes,
	})
}

// GetMetadata SAMLプロバイダーのSPメタデータを取得
func (h *SAMLHandler) GetMetadata(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	// SAMLAuthenticatorを取得
	authenticator, err := h.providerService.GetSAMLAuthenticator(providerID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get SAML authenticator")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if authenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SAML provider not found"})
		return
	}

	// メタデータXMLを生成
	metadata, err := authenticator.GenerateMetadata()
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate metadata")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate metadata"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"provider_id": providerID,
	}).Info("SP metadata generated")

	// XMLとして返す
	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, metadata)
}

// RegisterRoutes SAML認証のルートを登録
func (h *SAMLHandler) RegisterRoutes(router *gin.RouterGroup) {
	saml := router.Group("/saml")
	{
		saml.GET("/auth/:provider_id", h.InitiateAuth)
		saml.POST("/acs/:provider_id", h.HandleCallback)
		saml.GET("/metadata/:provider_id", h.GetMetadata)
	}
} 