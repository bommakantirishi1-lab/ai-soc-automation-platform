import os
from dotenv import load_dotenv
import logging

load_dotenv()

class Config:
    """Application configuration from environment variables"""
    
    # Telegram
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
    
    # SOC
    ANALYST_NAME = os.getenv("ANALYST_NAME", "SOC Analyst")
    ANALYST_ROLE = os.getenv("ANALYST_ROLE", "Security Operations")
    
    # Database
    DB_TYPE = os.getenv("DB_TYPE", "sqlite")
    DB_PATH = os.getenv("DB_PATH", "./data/soc_alerts.db")
    
    # ML & Logging
    ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "./models/alert_dedup_model.pkl")
    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "./logs/audit.log")
    MAX_ALERT_HISTORY = int(os.getenv("MAX_ALERT_HISTORY", "10000"))
    
    # Threat Feed
    THREAT_FEED_UPDATE_INTERVAL = int(os.getenv("THREAT_FEED_UPDATE_INTERVAL", "300"))
    ENABLE_LIVE_THREAT_MAP = os.getenv("ENABLE_LIVE_THREAT_MAP", "true").lower() == "true"
    
    # Performance
    CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"
    CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
    THREAD_POOL_SIZE = int(os.getenv("THREAD_POOL_SIZE", "4"))
    
    # Security
    DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

def setup_logging():
    """Setup logging with audit trail"""
    os.makedirs(os.path.dirname(Config.AUDIT_LOG_PATH) or ".", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.AUDIT_LOG_PATH),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

config = Config()
logger = setup_logging()
