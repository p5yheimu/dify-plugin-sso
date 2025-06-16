from typing import Dict, Any, Optional
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import structlog
from datetime import datetime

logger = structlog.get_logger()

class SAMLAuthenticator:
    """SAML 2.0認証処理クラス"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        SAML設定でAuthenticatorを初期化
        
        Args:
            config: SAML設定辞書
                - idp_url: IdP SSO URL
                - entity_id: SP Entity ID
                - x509_cert: IdP公開鍵証明書
                - sp_acs_url: SP ACS URL
                - sp_sls_url: SP SLS URL
        """
        self.config = config
        self.entity_id = config.get('entity_id')
        self.idp_url = config.get('idp_url')
        
    def create_auth_request(self, acs_url: str, relay_state: Optional[str] = None) -> Dict[str, str]:
        """
        SAML認証リクエストを生成
        
        Args:
            acs_url: Assertion Consumer Service URL
            relay_state: リレー状態（オプション）
            
        Returns:
            認証リクエスト情報（URL、SAMLRequest等）
        """
        try:
            # SAML設定作成
            saml_settings = self._build_saml_settings(acs_url)
            
            # 認証リクエスト生成
            auth = OneLogin_Saml2_Auth({}, saml_settings)
            sso_url = auth.login(return_to=relay_state)
            
            logger.info(
                "SAML auth request created",
                entity_id=self.entity_id,
                acs_url=acs_url,
                relay_state=relay_state
            )
            
            return {
                'sso_url': sso_url,
                'saml_request': auth.get_last_request_id(),
                'relay_state': relay_state
            }
            
        except Exception as e:
            logger.error(
                "Failed to create SAML auth request",
                entity_id=self.entity_id,
                error=str(e)
            )
            raise
    
    def validate_saml_response(self, saml_response: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        SAMLレスポンスを検証し、ユーザー情報を抽出
        
        Args:
            saml_response: Base64エンコードされたSAMLレスポンス
            request_id: 対応するリクエストID（オプション）
            
        Returns:
            検証結果とユーザー情報
        """
        try:
            # SAML設定作成
            saml_settings = self._build_saml_settings()
            
            # レスポンス検証
            auth = OneLogin_Saml2_Auth({}, saml_settings)
            auth.process_response(request_id)
            
            # エラーチェック
            errors = auth.get_errors()
            if errors:
                error_reason = auth.get_last_error_reason()
                logger.error(
                    "SAML response validation failed",
                    errors=errors,
                    error_reason=error_reason,
                    entity_id=self.entity_id
                )
                raise ValueError(f"SAML validation error: {error_reason}")
            
            # 認証済みかチェック
            if not auth.is_authenticated():
                logger.warning(
                    "SAML user not authenticated",
                    entity_id=self.entity_id
                )
                raise ValueError("User not authenticated")
            
            # ユーザー情報抽出
            user_data = {
                'name_id': auth.get_nameid(),
                'name_id_format': auth.get_nameid_format(),
                'attributes': auth.get_attributes(),
                'session_index': auth.get_session_index(),
                'session_expiration': auth.get_session_expiration()
            }
            
            logger.info(
                "SAML response validated successfully",
                entity_id=self.entity_id,
                name_id=user_data['name_id'],
                attributes_count=len(user_data['attributes'])
            )
            
            return {
                'success': True,
                'user_data': user_data
            }
            
        except Exception as e:
            logger.error(
                "Failed to validate SAML response",
                entity_id=self.entity_id,
                error=str(e)
            )
            raise
    
    def generate_sp_metadata(self, acs_url: str, sls_url: Optional[str] = None) -> str:
        """
        SPメタデータXMLを生成
        
        Args:
            acs_url: ACS URL
            sls_url: SLS URL（オプション）
            
        Returns:
            SPメタデータXML文字列
        """
        try:
            # SAML設定作成
            saml_settings = self._build_saml_settings(acs_url, sls_url)
            settings = OneLogin_Saml2_Settings(saml_settings)
            
            # メタデータ生成
            metadata = settings.get_sp_metadata()
            
            # メタデータ検証
            errors = settings.check_sp_metadata(metadata)
            if errors:
                logger.error(
                    "SP metadata validation failed",
                    errors=errors,
                    entity_id=self.entity_id
                )
                raise ValueError(f"SP metadata error: {errors}")
            
            logger.info(
                "SP metadata generated successfully",
                entity_id=self.entity_id,
                acs_url=acs_url
            )
            
            return metadata
            
        except Exception as e:
            logger.error(
                "Failed to generate SP metadata",
                entity_id=self.entity_id,
                error=str(e)
            )
            raise
    
    def _build_saml_settings(self, acs_url: Optional[str] = None, sls_url: Optional[str] = None) -> Dict[str, Any]:
        """
        SAML設定辞書を構築
        
        Args:
            acs_url: ACS URL
            sls_url: SLS URL
            
        Returns:
            SAML設定辞書
        """
        settings = {
            'sp': {
                'entityId': self.entity_id,
                'assertionConsumerService': {
                    'url': acs_url or self.config.get('sp_acs_url'),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                },
                'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                'x509cert': self.config.get('sp_x509_cert', ''),
                'privateKey': self.config.get('sp_private_key', '')
            },
            'idp': {
                'entityId': self.config.get('idp_entity_id'),
                'singleSignOnService': {
                    'url': self.idp_url,
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'x509cert': self.config.get('x509_cert')
            }
        }
        
        # SLS設定（オプション）
        if sls_url or self.config.get('sp_sls_url'):
            settings['sp']['singleLogoutService'] = {
                'url': sls_url or self.config.get('sp_sls_url'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            }
        
        if self.config.get('idp_sls_url'):
            settings['idp']['singleLogoutService'] = {
                'url': self.config.get('idp_sls_url'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            }
        
        # セキュリティ設定
        settings['security'] = {
            'nameIdEncrypted': False,
            'authnRequestsSigned': False,
            'logoutRequestSigned': False,
            'logoutResponseSigned': False,
            'signMetadata': False,
            'wantAssertionsSigned': True,
            'wantNameId': True,
            'wantAssertionsEncrypted': False,
            'wantNameIdEncrypted': False,
            'requestedAuthnContext': True,
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256'
        }
        
        return settings 