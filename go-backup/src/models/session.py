from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from src.models import Base

class Session(Base):
    __tablename__ = 'dify_sso_sessions'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(255), nullable=False)
    provider_id = Column(UUID(as_uuid=True), ForeignKey('dify_sso_providers.id'))
    session_data = Column(JSON)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now()) 