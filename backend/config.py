"""
Flask application configuration.

All sensitive values are read from environment variables.
Use .env.example as a template for your .env file.
"""

import os

from dotenv import load_dotenv

load_dotenv()


class _Base:
    SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    DEBUG: bool = False
    # Comma-separated list of allowed CORS origins
    ALLOWED_ORIGINS: list[str] = os.environ.get(
        "ALLOWED_ORIGINS",
        "https://scanguard.sg,https://snehuh.github.io",
    ).split(",")
    RATELIMIT_DEFAULT: str = "60 per minute"
    RATELIMIT_SCAN: str = "20 per minute"
    RATELIMIT_STORAGE_URI: str = os.environ.get("REDIS_URL", "memory://")
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


class Development(_Base):
    DEBUG = True
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        *_Base.ALLOWED_ORIGINS,
    ]


class Production(_Base):
    DEBUG = False

    @staticmethod
    def validate() -> None:
        """Raise if required production secrets are missing."""
        if not os.environ.get("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY environment variable must be set in production."
            )


_ENV_MAP = {
    "development": Development,
    "production": Production,
}


def get_config():
    """Return the config class for the current FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development")
    cfg = _ENV_MAP.get(env, Development)
    if hasattr(cfg, "validate"):
        cfg.validate()
    return cfg
