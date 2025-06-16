# Development Environment Setup 🚀

このプロジェクトはDevcontainerを使用したLinux環境での開発をサポートしています。

## 🏗️ **Devcontainer使用方法**

### **1. 前提条件**
- **VS Code** がインストール済み
- **Docker Desktop** が動作中
- **Dev Containers拡張機能** をインストール
  ```
  ext install ms-vscode-remote.remote-containers
  ```

### **2. 環境起動**
```bash
# 1. VS Codeでプロジェクトを開く
code .

# 2. コマンドパレット (Ctrl+Shift+P) で実行
> Dev Containers: Reopen in Container

# または、左下の><アイコン → "Reopen in Container"
```

### **3. 初回セットアップ（自動実行）**
```bash
# Go環境確認
go version && go env

# 依存関係ダウンロード
go mod download

# 開発ツールインストール
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## ⚡ **開発コマンド（Makefile）**

### **基本操作**
```bash
# ヘルプ表示
make help

# 依存関係整理
make tidy

# アプリケーションビルド
make build

# 開発サーバー起動（PostgreSQL使用）
make run
```

### **テスト実行**
```bash
# 全テスト実行
make test

# カバレッジ付きテスト
make test-cover
# → coverage.html が生成される
```

### **コード品質チェック**
```bash
# Lint実行
make lint

# CI全チェック（ローカル）
make ci-local
```

### **Docker開発**
```bash
# Dockerイメージビルド
make docker-build

# Dockerコンテナ実行
make docker-run
```

## 🗄️ **データベース設定**

### **PostgreSQL（開発用）**
```bash
# 接続情報
Host: localhost
Port: 5432
Database: dify_sso_dev
Username: postgres
Password: postgres

# 接続URL
DATABASE_URL=postgres://postgres:postgres@localhost:5432/dify_sso_dev?sslmode=disable
```

### **SQLite（テスト用）**
```bash
# ファイルベース
DATABASE_URL=sqlite:///dify_sso.db
```

## 🌐 **ポート設定**

- **8000**: SSO Server（メインアプリ）
- **5432**: PostgreSQL（データベース）

## 📁 **プロジェクト構造**

```
.
├── .devcontainer/          # Devcontainer設定
│   ├── devcontainer.json   # VS Code設定
│   └── docker-compose.yml  # サービス定義
├── .vscode/                # VS Code設定
├── cmd/sso-server/         # メインアプリケーション
├── internal/               # 内部パッケージ
│   ├── api/handlers/       # HTTPハンドラー
│   ├── auth/saml/          # SAML認証
│   ├── config/             # 設定管理
│   ├── models/             # データモデル
│   ├── repository/         # データアクセス
│   └── service/            # ビジネスロジック
├── go-backup/              # Python実装バックアップ
├── Makefile                # 開発タスク
└── README.md               # プロジェクト概要
```

## 🐛 **トラブルシューティング**

### **Go環境問題**
```bash
# Go環境再設定
go env -w GO111MODULE=on
go env -w GOPROXY=https://proxy.golang.org,direct

# モジュール再初期化
go mod tidy
```

### **PostgreSQL接続問題**
```bash
# PostgreSQLサービス確認
docker ps | grep postgres

# サービス再起動
docker-compose restart postgres
```

### **Devcontainer再構築**
```bash
# VS Codeコマンドパレット
> Dev Containers: Rebuild Container
```

## 🎯 **開発フロー**

1. **🏗️ 環境起動**: Devcontainerで開発環境開始
2. **🧪 テスト駆動**: `make test` でテスト実行
3. **💻 実装**: Go拡張機能でコーディング
4. **🔍 品質チェック**: `make lint` でコード品質確認
5. **🚀 CI確認**: `make ci-local` でCI前チェック
6. **📦 コミット**: Gitでバージョンコントロール

---

**🎉 Devcontainer環境でCIと同じLinux環境で開発可能！**
**同時10,000認証対応の高性能Dify SSO Pluginを効率的に開発できます！** 