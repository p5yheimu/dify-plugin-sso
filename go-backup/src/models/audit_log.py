from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
import uuid
from src.models import Base

class AuditLog(Base):
    __tablename__ = 'dify_sso_audit_logs'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False)
    user_id = Column(String(255))
    provider_id = Column(UUID(as_uuid=True), ForeignKey('dify_sso_providers.id'))
    ip_address = Column(String(45))  # INET型はPostgreSQLのみ
    user_agent = Column(String)
    event_data = Column(JSON)
    timestamp = Column(DateTime, server_default=func.now()) 