from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Form, Query
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from src.services.provider_service import ProviderService
from src.audit.logger import AuditLogger
import structlog

logger = structlog.get_logger()
router = APIRouter(prefix="/saml", tags=["saml"])

# Pydanticモデル定義
class SAMLAuthRequest(BaseModel):
    provider_id: str
    acs_url: str
    relay_state: Optional[str] = None

class SAMLAuthResponse(BaseModel):
    sso_url: str
    saml_request: str
    relay_state: Optional[str] = None

class SAMLUserInfo(BaseModel):
    name_id: str
    name_id_format: str
    attributes: dict
    session_index: Optional[str] = None

# 依存性注入
def get_provider_service() -> ProviderService:
    return ProviderService()

def get_audit_logger() -> AuditLogger:
    return AuditLogger()

@router.post("/auth", response_model=SAMLAuthResponse)
async def initiate_saml_auth(
    auth_request: SAMLAuthRequest,
    service: ProviderService = Depends(get_provider_service),
    audit: AuditLogger = Depends(get_audit_logger)
):
    """SAML認証を開始"""
    try:
        # プロバイダー取得
        authenticator = service.get_saml_authenticator(auth_request.provider_id)
        if not authenticator:
            raise HTTPException(
                status_code=404,
                detail="SAML provider not found"
            )
        
        # 認証リクエスト生成
        auth_data = authenticator.create_auth_request(
            acs_url=auth_request.acs_url,
            relay_state=auth_request.relay_state
        )
        
        # 監査ログ記録
        await audit.log_event(
            event_type="saml_auth_initiated",
            provider_id=auth_request.provider_id,
            details={
                "acs_url": auth_request.acs_url,
                "relay_state": auth_request.relay_state
            }
        )
        
        return SAMLAuthResponse(**auth_data)
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(
            "Failed to initiate SAML auth",
            provider_id=auth_request.provider_id,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/acs/{provider_id}")
async def saml_acs(
    provider_id: str,
    SAMLResponse: str = Form(...),
    RelayState: Optional[str] = Form(None),
    service: ProviderService = Depends(get_provider_service),
    audit: AuditLogger = Depends(get_audit_logger)
):
    """SAML Assertion Consumer Service - IdPからのレスポンスを処理"""
    try:
        # プロバイダー取得
        authenticator = service.get_saml_authenticator(provider_id)
        if not authenticator:
            raise HTTPException(
                status_code=404,
                detail="SAML provider not found"
            )
        
        # SAMLレスポンス検証
        validation_result = authenticator.validate_saml_response(SAMLResponse)
        
        if not validation_result.get('success'):
            # 監査ログ記録（失敗）
            await audit.log_event(
                event_type="saml_auth_failed",
                provider_id=provider_id,
                details={
                    "reason": "response_validation_failed",
                    "relay_state": RelayState
                }
            )
            raise HTTPException(
                status_code=400,
                detail="SAML response validation failed"
            )
        
        user_data = validation_result['user_data']
        
        # 監査ログ記録（成功）
        await audit.log_event(
            event_type="saml_auth_success",
            provider_id=provider_id,
            user_id=user_data['name_id'],
            details={
                "name_id_format": user_data['name_id_format'],
                "attributes_count": len(user_data['attributes']),
                "relay_state": RelayState
            }
        )
        
        # セッション作成（実装予定）
        # TODO: セッション管理の実装
        
        # リダイレクト先決定
        redirect_url = RelayState or "/dashboard"
        
        return RedirectResponse(url=redirect_url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to process SAML response",
            provider_id=provider_id,
            error=str(e)
        )
        
        # 監査ログ記録（エラー）
        await audit.log_event(
            event_type="saml_auth_error",
            provider_id=provider_id,
            details={
                "error": str(e),
                "relay_state": RelayState
            }
        )
        
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/metadata/{provider_id}")
async def get_sp_metadata(
    provider_id: str,
    acs_url: str = Query(..., description="ACS URL"),
    sls_url: Optional[str] = Query(None, description="SLS URL"),
    service: ProviderService = Depends(get_provider_service)
):
    """SPメタデータXMLを生成・取得"""
    try:
        # プロバイダー取得
        authenticator = service.get_saml_authenticator(provider_id)
        if not authenticator:
            raise HTTPException(
                status_code=404,
                detail="SAML provider not found"
            )
        
        # メタデータ生成
        metadata_xml = authenticator.generate_sp_metadata(
            acs_url=acs_url,
            sls_url=sls_url
        )
        
        logger.info(
            "SP metadata generated",
            provider_id=provider_id,
            acs_url=acs_url
        )
        
        return Response(
            content=metadata_xml,
            media_type="application/xml",
            headers={
                "Content-Disposition": f"attachment; filename=sp_metadata_{provider_id}.xml"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to generate SP metadata",
            provider_id=provider_id,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/sls/{provider_id}")
async def saml_sls(
    provider_id: str,
    SAMLRequest: Optional[str] = Query(None),
    SAMLResponse: Optional[str] = Query(None),
    RelayState: Optional[str] = Query(None),
    service: ProviderService = Depends(get_provider_service),
    audit: AuditLogger = Depends(get_audit_logger)
):
    """SAML Single Logout Service"""
    try:
        # プロバイダー取得
        authenticator = service.get_saml_authenticator(provider_id)
        if not authenticator:
            raise HTTPException(
                status_code=404,
                detail="SAML provider not found"
            )
        
        # 監査ログ記録
        await audit.log_event(
            event_type="saml_logout_initiated",
            provider_id=provider_id,
            details={
                "has_request": SAMLRequest is not None,
                "has_response": SAMLResponse is not None,
                "relay_state": RelayState
            }
        )
        
        # ログアウト処理（実装予定）
        # TODO: セッション無効化の実装
        
        # リダイレクト先決定
        redirect_url = RelayState or "/login"
        
        return RedirectResponse(url=redirect_url, status_code=302)
        
    except Exception as e:
        logger.error(
            "Failed to process SAML logout",
            provider_id=provider_id,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error") 