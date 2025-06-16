# Dify SSO Plugin - テストガイドライン

## 🎯 テスト戦略

### テストピラミッド
```
       🔺 E2E Tests (5%)
      🔺🔺 Integration Tests (25%)
    🔺🔺🔺🔺 Unit Tests (70%)
```

### 品質ゲート
- **コードカバレッジ**: 90%以上
- **単体テスト成功率**: 100%
- **統合テスト成功率**: 100%
- **パフォーマンステスト**: 基準値クリア

## 🧪 単体テスト

### テスト構造
```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from src.auth.saml_authenticator import SAMLAuthenticator

class TestSAMLAuthenticator:
    """SAML認証テストクラス"""
    
    @pytest.fixture
    def saml_config(self):
        """テスト用SAML設定"""
        return {
            'idp_url': 'https://test-idp.example.com/sso',
            'entity_id': 'test-sp',
            'x509_cert': 'LS0tLS1CRUdJTi...',
            'private_key': 'LS0tLS1CRUdJTi...'
        }
    
    @pytest.fixture
    def authenticator(self, saml_config):
        """テスト用認証器インスタンス"""
        return SAMLAuthenticator(saml_config)
    
    def test_initialize_authenticator(self, saml_config):
        """認証器初期化テスト"""
        # Given: 有効なSAML設定
        
        # When: 認証器を初期化
        auth = SAMLAuthenticator(saml_config)
        
        # Then: 正常に初期化される
        assert auth.entity_id == 'test-sp'
        assert auth.idp_url == 'https://test-idp.example.com/sso'
    
    def test_generate_auth_request(self, authenticator):
        """認証リクエスト生成テスト"""
        # Given: 初期化済み認証器
        
        # When: 認証リクエストを生成
        auth_request = authenticator.create_auth_request('https://sp.example.com/acs')
        
        # Then: 有効なリクエストが生成される
        assert auth_request.url.startswith('https://test-idp.example.com')
        assert 'SAMLRequest' in auth_request.url
        assert auth_request.relay_state is not None
```

### セキュリティ機能テスト
```python
class TestSecurityFeatures:
    """セキュリティ機能テスト"""
    
    def test_saml_signature_validation(self):
        """SAML署名検証テスト"""
        # Given: 無効な署名のSAMLレスポンス
        invalid_response = create_invalid_saml_response()
        
        # When: 署名検証を実行
        with pytest.raises(SecurityError, match="Invalid signature"):
            validator.validate_saml_response(invalid_response)
    
    def test_token_expiration_check(self):
        """トークン有効期限チェック"""
        # Given: 期限切れトークン
        expired_token = create_expired_jwt()
        
        # When: トークン検証を実行
        with pytest.raises(SecurityError, match="Token expired"):
            validator.validate_jwt_token(expired_token)
    
    def test_csrf_protection(self):
        """CSRF保護テスト"""
        # Given: CSRFトークンなしのリクエスト
        request = create_request_without_csrf()
        
        # When: リクエスト処理を実行
        with pytest.raises(SecurityError, match="CSRF token missing"):
            handler.process_request(request)
```

### モックとスタブ
```python
@pytest.fixture
def mock_idp_response():
    """IdPレスポンスのモック"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Subject>
                <saml:NameID>test@example.com</saml:NameID>
            </saml:Subject>
        </saml:Assertion>
    </samlp:Response>
    """
    return mock_response

@patch('requests.post')
def test_oauth_token_exchange(self, mock_post, mock_idp_response):
    """OAuthトークン交換テスト"""
    # Given: モックされたHTTPレスポンス
    mock_post.return_value = mock_idp_response
    
    # When: トークン交換を実行
    token = oauth_client.exchange_code_for_token('auth_code_123')
    
    # Then: トークンが正常に取得される
    assert token.access_token is not None
    assert token.expires_in > 0
```

## 🔗 統合テスト

### データベース統合テスト
```python
import pytest
from sqlalchemy import create_engine
from src.models import Base, Provider, Session

@pytest.fixture(scope="session")
def test_database():
    """テスト用データベース"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def db_session(test_database):
    """データベースセッション"""
    connection = test_database.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

class TestProviderCRUD:
    """プロバイダーCRUDテスト"""
    
    def test_create_saml_provider(self, db_session):
        """SAMLプロバイダー作成テスト"""
        # Given: SAMLプロバイダー設定
        provider_data = {
            'name': 'Test SAML Provider',
            'type': 'saml',
            'config': {
                'idp_url': 'https://test.example.com/sso',
                'entity_id': 'test-provider'
            }
        }
        
        # When: プロバイダーを作成
        provider = Provider(**provider_data)
        db_session.add(provider)
        db_session.commit()
        
        # Then: データベースに保存される
        saved_provider = db_session.query(Provider).filter_by(
            name='Test SAML Provider'
        ).first()
        assert saved_provider is not None
        assert saved_provider.type == 'saml'
```

### 外部API統合テスト
```python
import responses
import json

@responses.activate
def test_oauth_userinfo_endpoint():
    """OAuth UserInfo エンドポイントテスト"""
    # Given: モックされたUserInfoエンドポイント
    responses.add(
        responses.GET,
        'https://oauth.example.com/userinfo',
        json={
            'sub': '123456789',
            'email': 'test@example.com',
            'name': 'Test User'
        },
        status=200
    )
    
    # When: ユーザー情報を取得
    user_info = oauth_client.get_user_info('access_token_123')
    
    # Then: 正しいユーザー情報が取得される
    assert user_info['email'] == 'test@example.com'
    assert user_info['name'] == 'Test User'

@responses.activate  
def test_saml_metadata_retrieval():
    """SAMLメタデータ取得テスト"""
    # Given: モックされたメタデータエンドポイント
    metadata_xml = """
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <IDPSSODescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                               Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    """
    responses.add(
        responses.GET,
        'https://idp.example.com/metadata',
        body=metadata_xml,
        status=200,
        content_type='text/xml'
    )
    
    # When: メタデータを取得
    metadata = saml_client.fetch_metadata('https://idp.example.com/metadata')
    
    # Then: メタデータが正常に解析される
    assert metadata.sso_url == 'https://idp.example.com/sso'
```

## 🎭 E2Eテスト

### ブラウザ自動化テスト
```python
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

@pytest.fixture
def browser():
    """ブラウザインスタンス"""
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()

class TestSSOFlow:
    """SSOフローE2Eテスト"""
    
    def test_complete_saml_login_flow(self, browser):
        """完全なSAMLログインフローテスト"""
        # Given: Difyアプリケーションにアクセス
        browser.get('https://app.example.com/login')
        
        # When: SSOボタンをクリック
        sso_button = browser.find_element(By.ID, 'sso-login-btn')
        sso_button.click()
        
        # Then: IdPログインページにリダイレクト
        WebDriverWait(browser, 10).until(
            EC.url_contains('idp.example.com')
        )
        
        # When: IdPでログイン
        username_field = browser.find_element(By.ID, 'username')
        password_field = browser.find_element(By.ID, 'password')
        login_button = browser.find_element(By.ID, 'login-btn')
        
        username_field.send_keys('testuser@example.com')
        password_field.send_keys('testpassword')
        login_button.click()
        
        # Then: Difyアプリケーションにリダイレクトされる
        WebDriverWait(browser, 10).until(
            EC.url_contains('app.example.com/dashboard')
        )
        
        # And: ユーザーが認証される
        user_menu = browser.find_element(By.CLASS_NAME, 'user-menu')
        assert 'testuser@example.com' in user_menu.text
```

## ⚡ パフォーマンステスト

### レスポンス時間テスト
```python
import time
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class TestPerformance:
    """パフォーマンステスト"""
    
    def test_token_validation_performance(self):
        """トークン検証性能テスト"""
        # Given: 有効なJWTトークン
        token = generate_test_jwt()
        
        # When: トークン検証を実行（100回）
        start_time = time.time()
        for _ in range(100):
            result = jwt_validator.validate(token)
            assert result.is_valid
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Then: 平均レスポンス時間が50ms以内
        assert avg_time < 0.05, f"Average validation time: {avg_time:.3f}s"
    
    async def test_concurrent_authentication(self):
        """同時認証負荷テスト"""
        # Given: 複数の認証リクエスト
        async def auth_request(session, user_id):
            async with session.post('/auth/login', json={
                'username': f'user{user_id}@example.com',
                'password': 'testpass'
            }) as response:
                return await response.json()
        
        # When: 100個の同時リクエストを送信
        async with aiohttp.ClientSession() as session:
            tasks = [auth_request(session, i) for i in range(100)]
            start_time = time.time()
            results = await asyncio.gather(*tasks)
            end_time = time.time()
        
        # Then: 全リクエストが成功し、合計時間が5秒以内
        success_count = sum(1 for r in results if r.get('success'))
        total_time = end_time - start_time
        
        assert success_count == 100
        assert total_time < 5.0, f"Total time: {total_time:.2f}s"
```

### メモリ使用量テスト
```python
import psutil
import gc

def test_memory_usage_under_load():
    """負荷時のメモリ使用量テスト"""
    # Given: 初期メモリ使用量を記録
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # When: 大量の認証処理を実行
    for i in range(1000):
        auth_session = create_auth_session(f'user{i}')
        process_authentication(auth_session)
        
        # 100回ごとにガベージコレクション
        if i % 100 == 0:
            gc.collect()
    
    # Then: メモリ使用量が512MB以内
    final_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = final_memory - initial_memory
    
    assert final_memory < 512, f"Memory usage: {final_memory:.1f}MB"
    assert memory_increase < 100, f"Memory leak: {memory_increase:.1f}MB"
```

## 🛡️ セキュリティテスト

### 脆弱性テスト
```python
class TestSecurityVulnerabilities:
    """セキュリティ脆弱性テスト"""
    
    def test_sql_injection_protection(self):
        """SQLインジェクション耐性テスト"""
        malicious_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1' --",
            "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
            "1'; UPDATE users SET password='hacked' WHERE '1'='1"
        ]
        
        for payload in malicious_payloads:
            response = self.client.post('/auth/login', {
                'username': payload,
                'password': 'test'
            })
            
            # データベースエラーが露出していないことを確認
            assert response.status_code != 500
            assert 'database' not in response.text.lower()
            assert 'sql' not in response.text.lower()
    
    def test_xss_protection(self):
        """XSS攻撃耐性テスト"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            response = self.client.post('/config/provider', {
                'name': payload,
                'description': payload
            })
            
            # スクリプトがエスケープされていることを確認
            assert '<script>' not in response.text
            assert 'javascript:' not in response.text
            assert payload not in response.text
    
    def test_authentication_bypass(self):
        """認証バイパス耐性テスト"""
        bypass_attempts = [
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': 'admin'},
            {'username': 'admin', 'password': None},
            {'token': 'invalid_token'},
            {}  # 空のリクエスト
        ]
        
        for attempt in bypass_attempts:
            response = self.client.post('/auth/login', attempt)
            assert response.status_code in [400, 401, 403]
```

## 📊 テストデータ管理

### テストフィクスチャ
```python
# conftest.py
import pytest
from src.models import Provider, User

@pytest.fixture
def sample_saml_provider():
    """サンプルSAMLプロバイダー"""
    return Provider(
        name='Test SAML IdP',
        type='saml',
        config={
            'idp_url': 'https://test-idp.example.com/sso',
            'entity_id': 'test-idp',
            'x509_cert': '''-----BEGIN CERTIFICATE-----
MIIDEjCCAfqgAwIBAgIJAMmtFJ...
-----END CERTIFICATE-----''',
            'single_logout_url': 'https://test-idp.example.com/slo'
        }
    )

@pytest.fixture
def sample_user():
    """サンプルユーザー"""
    return User(
        email='test@example.com',
        name='Test User',
        provider_id='saml-test-provider'
    )

@pytest.fixture
def valid_saml_response():
    """有効なSAMLレスポンス"""
    return '''<?xml version="1.0" encoding="UTF-8"?>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                    test@example.com
                </saml:NameID>
            </saml:Subject>
        </saml:Assertion>
    </samlp:Response>'''
```

## 🔄 継続的テスト

### CI/CDでのテスト実行
```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run unit tests
      run: |
        pytest tests/unit/ --cov=src --cov-report=xml
    
    - name: Run integration tests
      run: |
        pytest tests/integration/
    
    - name: Run security tests
      run: |
        bandit -r src/
        safety check
        pytest tests/security/
    
    - name: Run performance tests
      run: |
        pytest tests/performance/ --benchmark-only
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### テストレポート
```python
# pytest.ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --verbose
    --tb=short
    --cov=src
    --cov-report=html:htmlcov
    --cov-report=term-missing
    --cov-fail-under=90
    --junit-xml=test-results.xml
```

このテストガイドラインに従って、信頼性の高いDify SSO Pluginを開発してください。テストは品質保証の要であり、継続的な改善の基盤となります。 