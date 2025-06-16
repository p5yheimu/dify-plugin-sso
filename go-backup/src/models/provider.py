from sqlalchemy import Column, String, DateTime, JSON, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from src.models import Base

class ProviderTypeEnum(str, Enum):
    saml = 'saml'
    oauth = 'oauth'
    oidc = 'oidc'

class Provider(Base):
    __tablename__ = 'dify_sso_providers'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)  # 'saml', 'oauth', 'oidc'
    config = Column(JSON, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now()) 