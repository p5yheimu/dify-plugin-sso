from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from src.config import Config

engine = create_engine(Config.DATABASE_URL, echo=Config.DEBUG, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# モデルをインポート
from src.models.provider import Provider
from src.models.session import Session
from src.models.audit_log import AuditLog

def init_db():
    Base.metadata.create_all(bind=engine) 