from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from src.models import SessionLocal
from src.models.audit_log import AuditLog
import structlog
from datetime import datetime
import json

logger = structlog.get_logger()

class AuditLogger:
    """監査ログ記録クラス"""
    
    def __init__(self):
        pass
    
    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        監査イベントを記録
        
        Args:
            event_type: イベントタイプ
            user_id: ユーザーID（オプション）
            provider_id: プロバイダーID（オプション）
            ip_address: IPアドレス（オプション）
            user_agent: ユーザーエージェント（オプション）
            details: 詳細情報（オプション）
        """
        db = SessionLocal()
        try:
            # 監査ログエントリ作成
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                provider_id=provider_id,
                ip_address=ip_address,
                user_agent=user_agent,
                event_data=details or {}
            )
            
            db.add(audit_log)
            db.commit()
            
            # 構造化ログにも出力
            logger.info(
                "audit_event",
                event_type=event_type,
                user_id=user_id,
                provider_id=provider_id,
                ip_address=ip_address,
                timestamp=datetime.utcnow().isoformat(),
                details=details or {}
            )
            
        except Exception as e:
            db.rollback()
            logger.error(
                "Failed to log audit event",
                event_type=event_type,
                user_id=user_id,
                provider_id=provider_id,
                error=str(e)
            )
            # 監査ログの失敗は再発生させない（アプリケーションを停止させない）
        finally:
            db.close()
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        監査イベントを検索・取得
        
        Args:
            event_type: フィルターするイベントタイプ
            user_id: フィルターするユーザーID
            provider_id: フィルターするプロバイダーID
            start_date: 開始日時
            end_date: 終了日時
            limit: 取得件数制限
            
        Returns:
            監査ログエントリのリスト
        """
        db = SessionLocal()
        try:
            query = db.query(AuditLog)
            
            # フィルター適用
            if event_type:
                query = query.filter(AuditLog.event_type == event_type)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            if provider_id:
                query = query.filter(AuditLog.provider_id == provider_id)
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            # 最新順にソート
            query = query.order_by(AuditLog.timestamp.desc())
            
            # 件数制限
            query = query.limit(limit)
            
            return query.all()
            
        except Exception as e:
            logger.error(
                "Failed to get audit events",
                event_type=event_type,
                user_id=user_id,
                provider_id=provider_id,
                error=str(e)
            )
            return []
        finally:
            db.close()
    
    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        機密データをマスク処理
        
        Args:
            data: 元データ
            
        Returns:
            マスク処理されたデータ
        """
        sensitive_fields = [
            'password', 'secret', 'token', 'key', 'private_key',
            'client_secret', 'x509_cert', 'saml_response'
        ]
        
        masked_data = {}
        for key, value in data.items():
            if any(field in key.lower() for field in sensitive_fields):
                if isinstance(value, str) and len(value) > 8:
                    masked_data[key] = value[:4] + '*' * (len(value) - 8) + value[-4:]
                else:
                    masked_data[key] = '***masked***'
            else:
                masked_data[key] = value
        
        return masked_data 