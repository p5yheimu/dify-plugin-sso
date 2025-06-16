# Dify SSO Plugin - Docker環境セットアップガイド

## 前提条件
- [Docker](https://www.docker.com/) 20.10以上
- （任意）[Docker Compose](https://docs.docker.com/compose/) 1.29以上
- PythonやPoetry等のローカルセットアップは不要

---

## 1. ソースコードの取得

```sh
git clone https://github.com/p5yheimu/dify-plugin-sso.git
cd dify-plugin-sso
```

---

## 2. 環境変数の設定

`.env` ファイルをプロジェクトルートに作成し、以下のように記述してください：

```env
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///dify_sso.db  # SQLite例
# DATABASE_URL=postgresql+psycopg2://user:password@db:5432/dify_sso  # PostgreSQL例
REDIS_URL=redis://localhost:6379/0
SSO_SESSION_TIMEOUT=28800
SSO_MAX_CONCURRENT_SESSIONS=5
SSO_AUDIT_LOG_RETENTION_DAYS=2555
DEBUG=True
```

---

## 3. Dockerイメージのビルド

```sh
docker build -t dify-sso-plugin:latest .
```

---

## 4. コンテナの起動

```sh
docker run --rm -it -p 8000:8000 --env-file .env dify-sso-plugin:latest
```

- `http://localhost:8000/health` でヘルスチェックができます

---

## 5. データベース永続化（PostgreSQL例）

`docker-compose.yml`例：

```yaml
version: '3.8'
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_USER: dify
      POSTGRES_PASSWORD: dify
      POSTGRES_DB: dify_sso
    ports:
      - "5432:5432"
    volumes:
      - db_data:/var/lib/postgresql/data
  app:
    build: .
    env_file: .env
    ports:
      - "8000:8000"
    depends_on:
      - db
volumes:
  db_data:
```

起動：
```sh
docker-compose up --build
```

---

## 6. マイグレーション・初期化

初回起動時に自動でDBテーブルが作成されます。

---

## 7. 開発・本番の切り替え
- `.env` の `DEBUG` を `True`（開発）/`False`（本番）で切り替え
- DBやRedisの接続先も `.env` で変更可能

---

## 8. よくあるトラブル
- ポート競合 → `-p` オプションで変更
- DB接続エラー → `.env` の `DATABASE_URL` 設定を確認
- 権限エラー → `USER` 指定やボリューム権限を確認

---

## 9. その他
- FastAPIのAPIドキュメント: `http://localhost:8000/docs`
- 本番運用時はHTTPSリバースプロキシ（nginx等）推奨

---

ご不明点はプロジェクト管理者までご連絡ください。 