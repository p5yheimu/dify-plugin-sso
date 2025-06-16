package repository

import (
	"fmt"
	"strings"

	"github.com/p5yheimu/dify-plugin-sso/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitDatabase データベースを初期化
func InitDatabase(databaseURL string, debug bool) (*gorm.DB, error) {
	// ログレベル設定
	logLevel := logger.Silent
	if debug {
		logLevel = logger.Info
	}

	config := &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	}

	var db *gorm.DB
	var err error

	// データベースタイプを判定して接続
	if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
		db, err = gorm.Open(postgres.Open(databaseURL), config)
	} else if strings.HasPrefix(databaseURL, "sqlite://") {
		// SQLiteの場合はsqlite://プレフィックスを除去
		sqliteFile := strings.TrimPrefix(databaseURL, "sqlite://")
		db, err = gorm.Open(sqlite.Open(sqliteFile), config)
	} else {
		// デフォルトはSQLite
		db, err = gorm.Open(sqlite.Open(databaseURL), config)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// マイグレーション実行
	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	logrus.Info("Database initialized successfully")
	return db, nil
}

// runMigrations データベースマイグレーションを実行
func runMigrations(db *gorm.DB) error {
	// 順序を考慮してマイグレーションを実行
	models := []interface{}{
		&models.Provider{},
		&models.Session{},
		&models.AuditLog{},
	}

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	// インデックスを作成
	if err := createIndexes(db); err != nil {
		return err
	}

	logrus.Info("Database migrations completed successfully")
	return nil
}

// createIndexes 必要なインデックスを作成
func createIndexes(db *gorm.DB) error {
	// Sessions テーブルのインデックス
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_sessions_user_id ON dify_sso_sessions(user_id)").Error; err != nil {
		return fmt.Errorf("failed to create user_id index: %w", err)
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_sessions_provider_id ON dify_sso_sessions(provider_id)").Error; err != nil {
		return fmt.Errorf("failed to create provider_id index: %w", err)
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_sessions_expires_at ON dify_sso_sessions(expires_at)").Error; err != nil {
		return fmt.Errorf("failed to create expires_at index: %w", err)
	}

	// Audit Logs テーブルのインデックス
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_audit_logs_event_type ON dify_sso_audit_logs(event_type)").Error; err != nil {
		return fmt.Errorf("failed to create event_type index: %w", err)
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_audit_logs_user_id ON dify_sso_audit_logs(user_id)").Error; err != nil {
		return fmt.Errorf("failed to create audit user_id index: %w", err)
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_audit_logs_timestamp ON dify_sso_audit_logs(timestamp)").Error; err != nil {
		return fmt.Errorf("failed to create timestamp index: %w", err)
	}

	// Providers テーブルのインデックス
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_providers_type ON dify_sso_providers(type)").Error; err != nil {
		return fmt.Errorf("failed to create provider type index: %w", err)
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_dify_sso_providers_name ON dify_sso_providers(name)").Error; err != nil {
		return fmt.Errorf("failed to create provider name index: %w", err)
	}

	logrus.Info("Database indexes created successfully")
	return nil
}

// CleanupExpiredSessions 期限切れセッションをクリーンアップ
func CleanupExpiredSessions(db *gorm.DB) error {
	result := db.Where("expires_at < NOW()").Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", result.Error)
	}

	if result.RowsAffected > 0 {
		logrus.WithField("deleted_sessions", result.RowsAffected).Info("Expired sessions cleaned up")
	}

	return nil
}

// CleanupOldAuditLogs 古い監査ログをクリーンアップ
func CleanupOldAuditLogs(db *gorm.DB, retentionDays int) error {
	result := db.Where("timestamp < NOW() - INTERVAL '? days'", retentionDays).Delete(&models.AuditLog{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup old audit logs: %w", result.Error)
	}

	if result.RowsAffected > 0 {
		logrus.WithField("deleted_logs", result.RowsAffected).Info("Old audit logs cleaned up")
	}

	return nil
} 