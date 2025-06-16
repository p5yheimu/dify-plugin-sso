package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/p5yheimu/dify-plugin-sso/internal/api/handlers"
	"github.com/p5yheimu/dify-plugin-sso/internal/config"
	"github.com/p5yheimu/dify-plugin-sso/internal/repository"
	"github.com/p5yheimu/dify-plugin-sso/internal/service"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func main() {
	// 設定読み込み
	cfg := config.Load()

	// ログ設定
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if cfg.Debug {
		gin.SetMode(gin.DebugMode)
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		gin.SetMode(gin.ReleaseMode)
		logrus.SetLevel(logrus.InfoLevel)
	}

	// データベース初期化
	db, err := repository.InitDatabase(cfg.DatabaseURL, cfg.Debug)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize database")
	}

	// サービス初期化
	providerService := service.NewProviderService(db)

	// ハンドラー初期化
	providerHandler := handlers.NewProviderHandler(providerService)
	samlHandler := handlers.NewSAMLHandler(providerService)

	// Ginルーター設定
	router := setupRouter(providerHandler, samlHandler)

	// HTTPサーバー設定
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort),
		Handler: router,
	}

	// バックグラウンドタスク開始
	go startBackgroundTasks(db, cfg)

	// サーバー開始
	go func() {
		logrus.WithFields(logrus.Fields{
			"host": cfg.ServerHost,
			"port": cfg.ServerPort,
		}).Info("Starting Dify SSO Plugin server")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Fatal("Failed to start server")
		}
	}()

	// グレースフルシャットダウン
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logrus.WithError(err).Fatal("Server forced to shutdown")
	}

	logrus.Info("Server exited")
}

// setupRouter Ginルーターを設定
func setupRouter(providerHandler *handlers.ProviderHandler, samlHandler *handlers.SAMLHandler) *gin.Engine {
	router := gin.New()

	// ミドルウェア設定
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// CORSミドルウェア
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// ヘルスチェック
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "dify-sso-plugin",
			"version": "1.0.0",
		})
	})

	// API v1 ルート
	v1 := router.Group("/api/v1")
	{
		providerHandler.RegisterRoutes(v1)
		samlHandler.RegisterRoutes(v1)
	}

	// 404ハンドラー
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Endpoint not found"})
	})

	return router
}

// startBackgroundTasks バックグラウンドタスクを開始
func startBackgroundTasks(db *gorm.DB, cfg *config.Config) {
	// セッションクリーンアップタスク（15分ごと）
	sessionCleanupTicker := time.NewTicker(15 * time.Minute)
	defer sessionCleanupTicker.Stop()

	// 監査ログクリーンアップタスク（1時間ごと）
	auditCleanupTicker := time.NewTicker(1 * time.Hour)
	defer auditCleanupTicker.Stop()

	for {
		select {
		case <-sessionCleanupTicker.C:
			if err := repository.CleanupExpiredSessions(db); err != nil {
				logrus.WithError(err).Error("Failed to cleanup expired sessions")
			}

		case <-auditCleanupTicker.C:
			if err := repository.CleanupOldAuditLogs(db, cfg.SSOAuditLogRetentionDays); err != nil {
				logrus.WithError(err).Error("Failed to cleanup old audit logs")
			}
		}
	}
} 