package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Config アプリケーション設定
type Config struct {
	// Server settings
	ServerHost string
	ServerPort string
	Debug      bool

	// Database settings
	DatabaseURL string

	// Redis settings
	RedisURL string

	// SSO settings
	SSOSessionTimeout        time.Duration
	SSOMaxConcurrentSessions int
	SSOAuditLogRetentionDays int

	// Security settings
	SecretKey string
}

// Load 設定を環境変数から読み込み
func Load() *Config {
	// .envファイルがあれば読み込み（エラーは無視）
	_ = godotenv.Load()

	config := &Config{
		ServerHost:               getEnv("SERVER_HOST", "0.0.0.0"),
		ServerPort:               getEnv("SERVER_PORT", "8000"),
		Debug:                    getEnvBool("DEBUG", false),
		DatabaseURL:              getEnv("DATABASE_URL", "sqlite:///dify_sso.db"),
		RedisURL:                 getEnv("REDIS_URL", "redis://localhost:6379/0"),
		SSOSessionTimeout:        time.Duration(getEnvInt("SSO_SESSION_TIMEOUT", 28800)) * time.Second,
		SSOMaxConcurrentSessions: getEnvInt("SSO_MAX_CONCURRENT_SESSIONS", 5),
		SSOAuditLogRetentionDays: getEnvInt("SSO_AUDIT_LOG_RETENTION_DAYS", 2555),
		SecretKey:                getEnv("SECRET_KEY", "changeme"),
	}

	if config.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	return config
}

// getEnv 環境変数を取得（デフォルト値付き）
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt 環境変数を整数として取得
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvBool 環境変数をブール値として取得
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
} 