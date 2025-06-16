from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from src.services.provider_service import ProviderService
import structlog

logger = structlog.get_logger()
router = APIRouter(prefix="/providers", tags=["providers"])

# Pydanticモデル定義
class ProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., regex="^(saml|oauth|oidc)$")
    config: dict

class ProviderUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[dict] = None

class ProviderResponse(BaseModel):
    id: str
    name: str
    type: str
    config: dict
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True

# 依存性注入
def get_provider_service() -> ProviderService:
    return ProviderService()

@router.post("/", response_model=ProviderResponse)
async def create_provider(
    provider_data: ProviderCreate,
    service: ProviderService = Depends(get_provider_service)
):
    """新しいSSOプロバイダーを作成"""
    try:
        # 設定検証
        if not service.validate_provider_config(provider_data.type, provider_data.config):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid configuration for {provider_data.type} provider"
            )
        
        # プロバイダー作成
        provider = service.create_provider(
            name=provider_data.name,
            provider_type=provider_data.type,
            config=provider_data.config
        )
        
        return ProviderResponse(
            id=str(provider.id),
            name=provider.name,
            type=provider.type,
            config=provider.config,
            created_at=provider.created_at.isoformat(),
            updated_at=provider.updated_at.isoformat()
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Failed to create provider", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/", response_model=List[ProviderResponse])
async def list_providers(
    type: Optional[str] = None,
    service: ProviderService = Depends(get_provider_service)
):
    """プロバイダー一覧を取得"""
    try:
        providers = service.list_providers(provider_type=type)
        
        return [
            ProviderResponse(
                id=str(provider.id),
                name=provider.name,
                type=provider.type,
                config=provider.config,
                created_at=provider.created_at.isoformat(),
                updated_at=provider.updated_at.isoformat()
            )
            for provider in providers
        ]
        
    except Exception as e:
        logger.error("Failed to list providers", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: str,
    service: ProviderService = Depends(get_provider_service)
):
    """特定のプロバイダーを取得"""
    try:
        provider = service.get_provider(provider_id)
        if not provider:
            raise HTTPException(status_code=404, detail="Provider not found")
        
        return ProviderResponse(
            id=str(provider.id),
            name=provider.name,
            type=provider.type,
            config=provider.config,
            created_at=provider.created_at.isoformat(),
            updated_at=provider.updated_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get provider", provider_id=provider_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: str,
    provider_data: ProviderUpdate,
    service: ProviderService = Depends(get_provider_service)
):
    """プロバイダーを更新"""
    try:
        # 設定検証（設定が提供されている場合）
        if provider_data.config:
            provider = service.get_provider(provider_id)
            if not provider:
                raise HTTPException(status_code=404, detail="Provider not found")
            
            if not service.validate_provider_config(provider.type, provider_data.config):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid configuration for {provider.type} provider"
                )
        
        # プロバイダー更新
        updated_provider = service.update_provider(
            provider_id=provider_id,
            name=provider_data.name,
            config=provider_data.config
        )
        
        if not updated_provider:
            raise HTTPException(status_code=404, detail="Provider not found")
        
        return ProviderResponse(
            id=str(updated_provider.id),
            name=updated_provider.name,
            type=updated_provider.type,
            config=updated_provider.config,
            created_at=updated_provider.created_at.isoformat(),
            updated_at=updated_provider.updated_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update provider", provider_id=provider_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/{provider_id}")
async def delete_provider(
    provider_id: str,
    service: ProviderService = Depends(get_provider_service)
):
    """プロバイダーを削除"""
    try:
        success = service.delete_provider(provider_id)
        if not success:
            raise HTTPException(status_code=404, detail="Provider not found")
        
        return {"message": "Provider deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete provider", provider_id=provider_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error") 