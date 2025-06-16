from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from src.models import SessionLocal
from src.models.provider import Provider, ProviderTypeEnum
from src.auth.saml import SAMLAuthenticator
import structlog
from datetime import datetime
import uuid

logger = structlog.get_logger()

class ProviderService:
    """SSOプロバイダー管理サービス"""
    
    def __init__(self):
        pass
    
    def create_provider(self, name: str, provider_type: str, config: Dict[str, Any]) -> Provider:
        """
        新しいSSOプロバイダーを作成
        
        Args:
            name: プロバイダー名
            provider_type: プロバイダータイプ ('saml', 'oauth', 'oidc')
            config: プロバイダー設定
            
        Returns:
            作成されたProviderオブジェクト
        """
        db = SessionLocal()
        try:
            # プロバイダー作成
            provider = Provider(
                name=name,
                type=provider_type,
                config=config
            )
            
            db.add(provider)
            db.commit()
            db.refresh(provider)
            
            logger.info(
                "Provider created",
                provider_id=str(provider.id),
                name=name,
                type=provider_type
            )
            
            return provider
            
        except Exception as e:
            db.rollback()
            logger.error(
                "Failed to create provider",
                name=name,
                type=provider_type,
                error=str(e)
            )
            raise
        finally:
            db.close()
    
    def get_provider(self, provider_id: str) -> Optional[Provider]:
        """
        プロバイダーIDでプロバイダーを取得
        
        Args:
            provider_id: プロバイダーID
            
        Returns:
            Providerオブジェクト（存在しない場合はNone）
        """
        db = SessionLocal()
        try:
            provider = db.query(Provider).filter(Provider.id == provider_id).first()
            return provider
        finally:
            db.close()
    
    def list_providers(self, provider_type: Optional[str] = None) -> List[Provider]:
        """
        プロバイダー一覧を取得
        
        Args:
            provider_type: フィルターするプロバイダータイプ（オプション）
            
        Returns:
            Providerオブジェクトのリスト
        """
        db = SessionLocal()
        try:
            query = db.query(Provider)
            if provider_type:
                query = query.filter(Provider.type == provider_type)
            
            return query.all()
        finally:
            db.close()
    
    def update_provider(self, provider_id: str, name: Optional[str] = None, 
                       config: Optional[Dict[str, Any]] = None) -> Optional[Provider]:
        """
        プロバイダーを更新
        
        Args:
            provider_id: プロバイダーID
            name: 新しい名前（オプション）
            config: 新しい設定（オプション）
            
        Returns:
            更新されたProviderオブジェクト（存在しない場合はNone）
        """
        db = SessionLocal()
        try:
            provider = db.query(Provider).filter(Provider.id == provider_id).first()
            if not provider:
                return None
            
            if name:
                provider.name = name
            if config:
                provider.config = config
            
            db.commit()
            db.refresh(provider)
            
            logger.info(
                "Provider updated",
                provider_id=provider_id,
                name=provider.name
            )
            
            return provider
            
        except Exception as e:
            db.rollback()
            logger.error(
                "Failed to update provider",
                provider_id=provider_id,
                error=str(e)
            )
            raise
        finally:
            db.close()
    
    def delete_provider(self, provider_id: str) -> bool:
        """
        プロバイダーを削除
        
        Args:
            provider_id: プロバイダーID
            
        Returns:
            削除成功の場合True、存在しない場合False
        """
        db = SessionLocal()
        try:
            provider = db.query(Provider).filter(Provider.id == provider_id).first()
            if not provider:
                return False
            
            db.delete(provider)
            db.commit()
            
            logger.info(
                "Provider deleted",
                provider_id=provider_id,
                name=provider.name
            )
            
            return True
            
        except Exception as e:
            db.rollback()
            logger.error(
                "Failed to delete provider",
                provider_id=provider_id,
                error=str(e)
            )
            raise
        finally:
            db.close()
    
    def get_saml_authenticator(self, provider_id: str) -> Optional[SAMLAuthenticator]:
        """
        SAMLプロバイダーのAuthenticatorを取得
        
        Args:
            provider_id: プロバイダーID
            
        Returns:
            SAMLAuthenticatorオブジェクト（SAMLプロバイダーでない場合はNone）
        """
        provider = self.get_provider(provider_id)
        if not provider or provider.type != 'saml':
            return None
        
        return SAMLAuthenticator(provider.config)
    
    def validate_provider_config(self, provider_type: str, config: Dict[str, Any]) -> bool:
        """
        プロバイダー設定を検証
        
        Args:
            provider_type: プロバイダータイプ
            config: 設定辞書
            
        Returns:
            設定が有効な場合True
        """
        try:
            if provider_type == 'saml':
                required_fields = ['idp_url', 'entity_id', 'x509_cert']
                return all(field in config for field in required_fields)
            
            elif provider_type == 'oauth':
                required_fields = ['client_id', 'client_secret', 'authorization_url', 'token_url']
                return all(field in config for field in required_fields)
            
            elif provider_type == 'oidc':
                required_fields = ['client_id', 'client_secret', 'discovery_url']
                return all(field in config for field in required_fields)
            
            return False
            
        except Exception as e:
            logger.error(
                "Provider config validation failed",
                provider_type=provider_type,
                error=str(e)
            )
            return False 