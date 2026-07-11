"""Application settings loaded from environment."""
from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Core
    ENV: str = "production"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    PROJECT_NAME: str = "VulnInt"
    API_V1_PREFIX: str = "/api/v1"
    TZ: str = "UTC"

    # DB
    DATABASE_URL: str
    SYNC_DATABASE_URL: str

    # Redis
    REDIS_URL: str
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    # OpenSearch
    OPENSEARCH_URL: str = "http://opensearch:9200"
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_VERIFY_CERTS: bool = False

    # Auth
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_HASH_ROUNDS: int = 12
    INITIAL_ADMIN_EMAIL: str = "admin@example.com"
    INITIAL_ADMIN_PASSWORD: str = "ChangeMeImmediately!1"

    # CORS
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 120

    # Feeds
    NVD_API_KEY: Optional[str] = None
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    UBUNTU_USN_FEED: str = "https://ubuntu.com/security/notices.json"
    DEBIAN_DSA_FEED: str = "https://security-tracker.debian.org/tracker/data/json"
    ALMALINUX_ERRATA_FEED: str = "https://errata.almalinux.org/feed/errata-rss.xml"
    ROCKY_ERRATA_FEED: str = "https://errata.rockylinux.org/api/v2/advisories"
    CLOUDLINUX_FEED: str = "https://cloudlinux.com/security-advisories/feed"
    MSRC_FEED: str = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
    CPANEL_FEED: str = "https://news.cpanel.com/category/security/feed/"
    CISA_KEV_FEED: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EXPLOITDB_FEED: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    # Alerts
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "alerts@example.com"
    SMTP_TLS: bool = True
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None
    SLACK_WEBHOOK_URL: Optional[str] = None
    SIEM_WEBHOOK_URL: Optional[str] = None
    ALERT_SEVERITY_THRESHOLD: str = "high"
    ALERT_KEV_ALWAYS: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def split_cors(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                import json
                return json.loads(v)
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
