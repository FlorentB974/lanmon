from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Literal, Optional


class Settings(BaseSettings):
    """Application settings."""
    
    # Application
    APP_NAME: str = "LAN Monitor"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./lanmon.db"
    
    # Network Scanning
    SCAN_INTERVAL: int = 120  # seconds
    SCAN_TIMEOUT: int = 5  # seconds per host for ARP responses
    SCAN_RETRIES: int = 2  # number of ARP scan attempts
    OFFLINE_GRACE_SCANS: int = 3  # missed scans before marking device offline
    DEFAULT_SUBNET: Optional[str] = None  # Auto-detect if None
    
    # Deep Scan Optimization
    DEEP_SCAN_PERIODIC_REFRESH_DAYS: int = 7  # Refresh useful identity profiles
    DEEP_SCAN_INCOMPLETE_REFRESH_HOURS: int = 24
    IDENTIFY_COOLDOWN_SECONDS: int = 60

    # Optional read-only DHCP lease enrichment. ``auto`` recognizes dnsmasq's
    # five-column format and the normalized JSON format documented in README.
    DHCP_LEASE_FILE: Optional[str] = None
    DHCP_LEASE_FORMAT: Literal["auto", "dnsmasq", "json"] = "auto"
    
    # CORS
    CORS_ORIGINS: list[str] = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
