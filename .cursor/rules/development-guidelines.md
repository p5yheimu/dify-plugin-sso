# Dify SSO Plugin - 開発ガイドライン

## 🎯 プロジェクト固有開発ルール

### Dify Plugin SDK制約
- プラグインサイズ制限: 最大50MB
- メモリ使用量制限: 最大512MB  
- API呼び出しレート: 100req/sec
- ファイルシステム: 読み取り専用（設定除く）

### プラグイン実装規約
```python
# プラグインエントリーポイント
class DifySSOPlugin:
    def __init__(self):
        self.name = "sso"
        self.version = "1.0.0"
        self.description = "Enterprise SSO Authentication Plugin"
    
    def configure(self, config: Dict[str, Any]) -> None:
        """プラグイン設定"""
        pass
    
    def authenticate(self, request: AuthRequest) -> AuthResponse:
        """認証処理のメインエントリーポイント"""
        pass
```

## 🔧 SSO実装特有ルール

### SAML 2.0実装
```python
# python3-samlライブラリ使用必須
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# メタデータ生成
def generate_metadata():
    settings = OneLogin_Saml2_Settings(saml_settings)
    metadata = settings.get_sp_metadata()
    return metadata

# レスポンス検証必須項目
def validate_saml_response(response):
    # 署名検証
    # タイムスタンプ検証
    # Audience制限確認
    # Subject確認
    pass
```

### OAuth 2.0/OpenID Connect実装
```python
# authlibライブラリ使用
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt

# PKCE必須実装
def create_auth_request():
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    return {
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

# JWT検証
def verify_jwt_token(token, public_key):
    try:
        payload = jwt.decode(token, public_key)
        return payload
    except Exception as e:
        logger.error(f"JWT verification failed: {e}")
        raise
```

## 🗄️ データベース設計規約

### テーブル命名規則
```sql
-- プレフィックス: dify_sso_
CREATE TABLE dify_sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'saml', 'oauth', 'oidc'
    config JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE dify_sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    provider_id UUID REFERENCES dify_sso_providers(id),
    session_data JSONB,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 🛡️ セキュリティ実装規約

### 入力検証
```python
from marshmallow import Schema, fields, validate

class SAMLConfigSchema(Schema):
    idp_url = fields.Url(required=True)
    entity_id = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    certificate = fields.Str(required=True)
    
class OAuthConfigSchema(Schema):
    client_id = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    client_secret = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    redirect_uri = fields.Url(required=True)
```

### ログ記録規約
```python
import structlog
from datetime import datetime

# 構造化ログ設定
logger = structlog.get_logger()

# 認証イベントログ
def log_auth_event(event_type: str, user_id: str = None, 
                  provider_id: str = None, **kwargs):
    logger.info(
        "auth_event",
        event_type=event_type,
        user_id=user_id,
        provider_id=provider_id,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs
    )

# 使用例
log_auth_event(
    event_type="saml_login_success",
    user_id="user123",
    provider_id="provider456",
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0..."
)
```

## 🧪 テスト実装規約

### 認証フローテスト
```python
import pytest
from unittest.mock import Mock, patch

class TestSAMLAuth:
    @pytest.fixture
    def saml_config(self):
        return {
            'idp_url': 'https://idp.example.com/sso',
            'entity_id': 'test-sp',
            'certificate': '-----BEGIN CERTIFICATE-----...'
        }
    
    def test_saml_login_flow(self, saml_config):
        # Given: 有効なSAML設定
        auth = SAMLAuthenticator(saml_config)
        
        # When: ログインリクエスト
        with patch('onelogin.saml2.auth.OneLogin_Saml2_Auth'):
            result = auth.initiate_login('https://sp.example.com/acs')
        
        # Then: リダイレクトURLが生成される
        assert result.redirect_url.startswith('https://idp.example.com')
        assert 'SAMLRequest' in result.redirect_url

    def test_saml_response_validation(self, saml_config):
        # セキュリティテスト必須項目
        # - 無効な署名の検証
        # - 期限切れアサーションの拒否
        # - 不正なAudienceの拒否
        pass
```

### パフォーマンステスト
```python
import time
import asyncio

class TestPerformance:
    def test_token_validation_performance(self):
        """トークン検証は50ms以内"""
        start = time.time()
        result = validate_jwt_token(sample_token, public_key)
        duration = time.time() - start
        
        assert duration < 0.05  # 50ms
        assert result is not None

    async def test_concurrent_auth_requests(self):
        """同時認証リクエスト処理"""
        tasks = []
        for i in range(100):
            task = asyncio.create_task(
                authenticate_user(f"user{i}", "password")
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        success_count = sum(1 for r in results if r.success)
        assert success_count == 100
```

## 📊 監視・メトリクス実装

### カスタムメトリクス
```python
from prometheus_client import Counter, Histogram, Gauge

# 認証メトリクス
auth_attempts_total = Counter(
    'dify_sso_auth_attempts_total',
    'Total authentication attempts',
    ['provider_type', 'result']
)

auth_duration = Histogram(
    'dify_sso_auth_duration_seconds',
    'Authentication duration',
    ['provider_type']
)

active_sessions = Gauge(
    'dify_sso_active_sessions',
    'Number of active SSO sessions'
)

# 使用例
def authenticate_user(username, provider):
    with auth_duration.labels(provider_type=provider.type).time():
        try:
            result = perform_authentication(username, provider)
            auth_attempts_total.labels(
                provider_type=provider.type,
                result='success'
            ).inc()
            return result
        except Exception as e:
            auth_attempts_total.labels(
                provider_type=provider.type,
                result='failure'
            ).inc()
            raise
```

## 🔄 設定管理規約

### 環境別設定
```python
# config/base.py
class BaseConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DATABASE_URL = os.environ.get('DATABASE_URL')
    REDIS_URL = os.environ.get('REDIS_URL')
    
    # SSO固有設定
    SSO_SESSION_TIMEOUT = 28800  # 8時間
    SSO_MAX_CONCURRENT_SESSIONS = 5
    SSO_AUDIT_LOG_RETENTION_DAYS = 2555  # 7年

# config/development.py
class DevelopmentConfig(BaseConfig):
    DEBUG = True
    DATABASE_URL = 'sqlite:///dev.db'
    
# config/production.py  
class ProductionConfig(BaseConfig):
    DEBUG = False
    # 本番環境では必ずPostgreSQL
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # セキュリティ強化
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
```

## 🚀 デプロイメント規約

### Docker設定
```dockerfile
# Dockerfile
FROM python:3.9-slim

# セキュリティ: 非rootユーザー作成
RUN useradd --create-home --shell /bin/bash dify-sso
WORKDIR /app

# 依存関係インストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションコピー
COPY --chown=dify-sso:dify-sso . .
USER dify-sso

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:create_app()"]
```

### CI/CD必須チェック
```yaml
# .github/workflows/ci.yml
- name: Security Scan
  run: |
    bandit -r src/
    safety check
    semgrep --config=auto src/

- name: Performance Test
  run: |
    pytest tests/performance/ --benchmark-only

- name: Integration Test
  run: |
    docker-compose -f docker-compose.test.yml up -d
    pytest tests/integration/
    docker-compose -f docker-compose.test.yml down
```

このガイドラインに従って、Dify SSO Pluginの開発を進めてください。セキュリティとパフォーマンスを最優先に、エンタープライズグレードの品質を維持することが重要です。 