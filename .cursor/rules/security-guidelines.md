# Dify SSO Plugin - セキュリティガイドライン

## 🔒 セキュリティ基本原則

### ゼロトラスト原則
- 全てのリクエストを検証する
- 最小権限の原則を適用する
- 定期的なアクセス権見直し
- 継続的な監視とログ記録

### 多層防御
- ネットワークレベル（TLS 1.3）
- アプリケーションレベル（入力検証）
- データレベル（暗号化）
- 監査レベル（ログ・監視）

## 🛡️ 認証セキュリティ

### SAML 2.0セキュリティ
```python
# 必須セキュリティチェック
def validate_saml_assertion(assertion):
    # 1. 署名検証
    if not verify_signature(assertion):
        raise SecurityError("Invalid SAML signature")
    
    # 2. タイムスタンプ検証
    if is_expired(assertion.conditions):
        raise SecurityError("SAML assertion expired")
    
    # 3. Audience制限
    if not validate_audience(assertion.audience_restriction):
        raise SecurityError("Invalid audience")
    
    # 4. Subject確認
    if not validate_subject_confirmation(assertion.subject):
        raise SecurityError("Invalid subject confirmation")
    
    return True
```

### OAuth 2.0セキュリティ
```python
# PKCE実装必須
def create_authorization_request():
    code_verifier = secrets.token_urlsafe(128)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

# 状態パラメータでCSRF防止
def generate_state_parameter():
    return secrets.token_urlsafe(32)
```

## 🔐 暗号化実装

### データ暗号化
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class FieldEncryption:
    def __init__(self, password: bytes, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        return self.cipher.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        return self.cipher.decrypt(ciphertext.encode()).decode()

# 使用対象
# - IdP証明書秘密鍵
# - OAuth クライアントシークレット
# - セッション暗号化キー
# - 一時的な認証トークン
```

### パスワードハッシュ化
```python
import bcrypt

def hash_password(password: str) -> str:
    # bcrypt使用（コスト12以上）
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
```

## 🚫 入力検証・サニタイゼーション

### 必須検証項目
```python
from marshmallow import Schema, fields, validate, ValidationError
import re

class SecureInputSchema(Schema):
    # URL検証
    callback_url = fields.Url(
        required=True,
        schemes=['https'],  # HTTPSのみ許可
        validate=validate.Length(max=2048)
    )
    
    # ドメイン制限
    entity_id = fields.Str(
        required=True,
        validate=[
            validate.Length(min=1, max=255),
            validate.Regexp(r'^[a-zA-Z0-9._-]+$')  # 安全な文字のみ
        ]
    )
    
    # XML/HTMLエスケープ
    description = fields.Str(
        validate=validate.Length(max=1000),
        missing=""
    )

def sanitize_input(data: dict) -> dict:
    """入力データのサニタイゼーション"""
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            # HTMLエスケープ
            value = html.escape(value)
            # SQL文字列のエスケープ
            value = value.replace("'", "''")
            # スクリプトタグ除去
            value = re.sub(r'<script.*?</script>', '', value, flags=re.IGNORECASE)
        sanitized[key] = value
    return sanitized
```

### SQL インジェクション対策
```python
# 必ずパラメータ化クエリを使用
def get_user_by_email(email: str):
    # ✅ 正しい実装
    query = "SELECT * FROM users WHERE email = %s"
    return db.execute(query, (email,))

def search_users(name: str):
    # ❌ 危険な実装（禁止）
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)
```

## 🔍 監査・ログ記録

### セキュリティイベントログ
```python
import structlog
from enum import Enum

class SecurityEventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_ACCESS = "data_access"
    CONFIG_CHANGE = "config_change"

logger = structlog.get_logger()

def log_security_event(
    event_type: SecurityEventType,
    user_id: str = None,
    ip_address: str = None,
    user_agent: str = None,
    details: dict = None
):
    logger.info(
        "security_event",
        event_type=event_type.value,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        timestamp=datetime.utcnow().isoformat(),
        details=details or {}
    )

# 使用例
def handle_login_attempt(username, success, ip_addr):
    if success:
        log_security_event(
            SecurityEventType.LOGIN_SUCCESS,
            user_id=username,
            ip_address=ip_addr
        )
    else:
        log_security_event(
            SecurityEventType.LOGIN_FAILURE,
            user_id=username,
            ip_address=ip_addr,
            details={'reason': 'invalid_credentials'}
        )
```

### 個人情報マスキング
```python
import re

def mask_sensitive_data(data: dict) -> dict:
    """ログ出力時の個人情報マスキング"""
    sensitive_fields = [
        'password', 'secret', 'token', 'key',
        'email', 'phone', 'ssn', 'credit_card'
    ]
    
    masked = {}
    for key, value in data.items():
        if any(field in key.lower() for field in sensitive_fields):
            if isinstance(value, str) and len(value) > 4:
                masked[key] = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                masked[key] = '***'
        else:
            masked[key] = value
    
    return masked
```

## 🚨 セキュリティインシデント対応

### 異常検知
```python
from collections import defaultdict
from datetime import datetime, timedelta

class AnomalyDetector:
    def __init__(self):
        self.login_attempts = defaultdict(list)
        self.failed_attempts_threshold = 5
        self.time_window = timedelta(minutes=15)
    
    def check_brute_force(self, ip_address: str, success: bool) -> bool:
        """ブルートフォース攻撃検知"""
        now = datetime.utcnow()
        
        if not success:
            self.login_attempts[ip_address].append(now)
        
        # 時間窓内の失敗回数をカウント
        recent_attempts = [
            attempt for attempt in self.login_attempts[ip_address]
            if now - attempt <= self.time_window
        ]
        
        if len(recent_attempts) >= self.failed_attempts_threshold:
            log_security_event(
                SecurityEventType.SUSPICIOUS_ACTIVITY,
                ip_address=ip_address,
                details={'type': 'brute_force_detected'}
            )
            return True
        
        return False
```

### インシデント対応手順
```python
class SecurityIncidentHandler:
    def handle_incident(self, incident_type: str, details: dict):
        """セキュリティインシデント対応"""
        
        if incident_type == "brute_force":
            self._block_ip(details['ip_address'])
            self._notify_admin(incident_type, details)
        
        elif incident_type == "data_breach":
            self._emergency_lockdown()
            self._notify_authorities(details)
        
        elif incident_type == "privilege_escalation":
            self._revoke_user_sessions(details['user_id'])
            self._audit_user_activities(details['user_id'])
    
    def _block_ip(self, ip_address: str):
        """IPアドレスブロック"""
        # ファイアウォールルール追加
        pass
    
    def _emergency_lockdown(self):
        """緊急ロックダウン"""
        # 全セッション無効化
        # サービス一時停止
        pass
```

## 🔄 セキュリティテスト

### ペネトレーションテスト
```python
import pytest
import requests

class TestSecurityVulnerabilities:
    def test_sql_injection_protection(self):
        """SQLインジェクション耐性テスト"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/*",
            "1' UNION SELECT password FROM users--"
        ]
        
        for payload in malicious_inputs:
            response = self.client.post('/auth/login', {
                'username': payload,
                'password': 'test'
            })
            # データベースエラーが露出していないことを確認
            assert 'database' not in response.text.lower()
            assert 'sql' not in response.text.lower()
    
    def test_xss_protection(self):
        """XSS攻撃耐性テスト"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            response = self.client.post('/config/provider', {
                'name': payload,
                'description': payload
            })
            # スクリプトが実行されていないことを確認
            assert '<script>' not in response.text
            assert 'javascript:' not in response.text
    
    def test_csrf_protection(self):
        """CSRF攻撃耐性テスト"""
        # CSRFトークンなしでリクエスト
        response = self.client.post('/config/update', {
            'setting': 'value'
        })
        assert response.status_code == 403
```

## 📋 セキュリティチェックリスト

### 開発時チェック項目
- [ ] 全ての入力値にバリデーション実装
- [ ] SQLインジェクション対策実装
- [ ] XSS対策実装  
- [ ] CSRF対策実装
- [ ] 機密データの暗号化実装
- [ ] 適切なセッション管理実装
- [ ] セキュリティヘッダー設定
- [ ] エラーハンドリングで情報漏洩なし

### デプロイ前チェック項目
- [ ] セキュリティスキャン実行
- [ ] ペネトレーションテスト実行
- [ ] 依存関係の脆弱性チェック
- [ ] 設定ファイルの機密情報確認
- [ ] ログ設定の個人情報マスキング確認
- [ ] HTTPS設定確認
- [ ] セキュリティモニタリング設定

セキュリティは継続的なプロセスです。定期的な見直しと改善を行ってください。 