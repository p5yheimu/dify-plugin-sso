import pytest
from unittest.mock import Mock, patch
from src.auth.saml import SAMLAuthenticator

class TestSAMLAuthenticator:
    """SAML認証テストクラス"""
    
    @pytest.fixture
    def saml_config(self):
        """テスト用SAML設定"""
        return {
            'idp_url': 'https://test-idp.example.com/sso',
            'entity_id': 'test-sp',
            'x509_cert': 'LS0tLS1CRUdJTi...',
            'idp_entity_id': 'test-idp',
            'sp_acs_url': 'https://sp.example.com/acs',
            'sp_sls_url': 'https://sp.example.com/sls'
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
    
    def test_build_saml_settings(self, authenticator):
        """SAML設定構築テスト"""
        # Given: 初期化済み認証器
        
        # When: SAML設定を構築
        settings = authenticator._build_saml_settings('https://sp.example.com/acs')
        
        # Then: 適切な設定が生成される
        assert settings['sp']['entityId'] == 'test-sp'
        assert settings['sp']['assertionConsumerService']['url'] == 'https://sp.example.com/acs'
        assert settings['idp']['singleSignOnService']['url'] == 'https://test-idp.example.com/sso'
        assert settings['security']['wantAssertionsSigned'] == True
    
    @patch('src.auth.saml.OneLogin_Saml2_Auth')
    def test_create_auth_request(self, mock_auth_class, authenticator):
        """認証リクエスト生成テスト"""
        # Given: モックされたOneLogin_Saml2_Auth
        mock_auth = Mock()
        mock_auth.login.return_value = 'https://idp.example.com/sso?SAMLRequest=...'
        mock_auth.get_last_request_id.return_value = 'request_123'
        mock_auth_class.return_value = mock_auth
        
        # When: 認証リクエストを生成
        result = authenticator.create_auth_request('https://sp.example.com/acs', 'relay123')
        
        # Then: 正しいリクエストが生成される
        assert 'sso_url' in result
        assert 'saml_request' in result
        assert result['relay_state'] == 'relay123'
        mock_auth.login.assert_called_once_with(return_to='relay123')
    
    @patch('src.auth.saml.OneLogin_Saml2_Auth')
    def test_validate_saml_response_success(self, mock_auth_class, authenticator):
        """SAMLレスポンス検証成功テスト"""
        # Given: 成功するSAMLレスポンス
        mock_auth = Mock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = 'test@example.com'
        mock_auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        mock_auth.get_attributes.return_value = {'email': ['test@example.com']}
        mock_auth.get_session_index.return_value = 'session_123'
        mock_auth.get_session_expiration.return_value = None
        mock_auth_class.return_value = mock_auth
        
        # When: SAMLレスポンスを検証
        result = authenticator.validate_saml_response('saml_response_b64')
        
        # Then: 成功結果が返される
        assert result['success'] == True
        assert result['user_data']['name_id'] == 'test@example.com'
        assert 'email' in result['user_data']['attributes']
    
    @patch('src.auth.saml.OneLogin_Saml2_Auth')
    def test_validate_saml_response_error(self, mock_auth_class, authenticator):
        """SAMLレスポンス検証エラーテスト"""
        # Given: エラーのあるSAMLレスポンス
        mock_auth = Mock()
        mock_auth.get_errors.return_value = ['invalid_signature']
        mock_auth.get_last_error_reason.return_value = 'Invalid SAML signature'
        mock_auth_class.return_value = mock_auth
        
        # When & Then: 検証エラーが発生する
        with pytest.raises(ValueError, match="SAML validation error"):
            authenticator.validate_saml_response('invalid_saml_response')
    
    @patch('src.auth.saml.OneLogin_Saml2_Settings')
    def test_generate_sp_metadata(self, mock_settings_class, authenticator):
        """SPメタデータ生成テスト"""
        # Given: モックされたSettings
        mock_settings = Mock()
        mock_settings.get_sp_metadata.return_value = '<EntityDescriptor>...</EntityDescriptor>'
        mock_settings.check_sp_metadata.return_value = []
        mock_settings_class.return_value = mock_settings
        
        # When: SPメタデータを生成
        metadata = authenticator.generate_sp_metadata('https://sp.example.com/acs')
        
        # Then: メタデータXMLが生成される
        assert metadata == '<EntityDescriptor>...</EntityDescriptor>'
        mock_settings.get_sp_metadata.assert_called_once()
        mock_settings.check_sp_metadata.assert_called_once()
    
    def test_invalid_config(self):
        """無効な設定での初期化テスト"""
        # Given: 不完全な設定
        invalid_config = {'entity_id': 'test-sp'}
        
        # When: 認証器を初期化
        auth = SAMLAuthenticator(invalid_config)
        
        # Then: idp_urlがNoneになる
        assert auth.idp_url is None 