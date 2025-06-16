import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'changeme')
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///dify_sso.db')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    SSO_SESSION_TIMEOUT = int(os.environ.get('SSO_SESSION_TIMEOUT', 28800))  # 8時間
    SSO_MAX_CONCURRENT_SESSIONS = int(os.environ.get('SSO_MAX_CONCURRENT_SESSIONS', 5))
    SSO_AUDIT_LOG_RETENTION_DAYS = int(os.environ.get('SSO_AUDIT_LOG_RETENTION_DAYS', 2555))  # 7年
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true' 