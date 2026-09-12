from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings and configuration

    This class manages all application settings including database,
    Redis, JWT, and other service configurations.
    """

    # Environment configuration
    ENV: str = "development"  # development, preview, or production

    # Basic configuration
    PROJECT_NAME: str = "FastAPI Template"
    API_V1_STR: str = "/api/v1"
    API_PORT: int = 8001  # Default API server port

    # Docker port configuration (optional, for docker-compose)
    REDIS_EXTERNAL_PORT: int = 6386  # External Redis port
    NGINX_HTTP_PORT: int = 8086
    NGINX_HTTPS_PORT: int = 8446
    FLOWER_PORT: int = 5556

    # Database configuration
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432  # Default PostgreSQL port
    POSTGRES_DB: str
    # Database SSL/TLS configuration (enabled in production for security)
    POSTGRES_SSL_REQUIRE: bool = False  # Set to True in production

    # Redis configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379  # Default Redis port
    REDIS_PASSWORD: str = ""

    # Celery configuration
    CELERY_BROKER_URL: str = ""  # Will be set in __init__
    CELERY_RESULT_BACKEND: str = ""  # Will be set in __init__

    # HTTP proxy configuration - only used in test environment
    USE_HTTP_PROXY: bool = False  # Default not to use proxy
    HTTP_PROXY: str = "http://127.0.0.1:7890"
    HTTPS_PROXY: str = "http://127.0.0.1:7890"

    # Email configuration
    MAIL_MAILER: str = "smtp"
    MAIL_HOST: str = "localhost"
    MAIL_PORT: int = 1025
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM_ADDRESS: str = "noreply@example.com"
    MAIL_FROM_NAME: str = "name"
    MAIL_ENCRYPTION: str = "none"

    # Brevo configuration (alternative email provider)
    BREVO_API_KEY: str = ""
    BREVO_EMAIL_FROM: str = "noreply@example.com"
    BREVO_EMAIL_FROM_NAME: str = "name"

    # Administrator email
    ADMIN_EMAIL: str = "dev@zetos.fr"

    # JWT configuration
    # SECURITY: SECRET_KEY MUST be set in .env file!
    # Generate secure key: python -c "import secrets; print(secrets.token_urlsafe(32))"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # S3 configuration
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"
    AWS_BUCKET_NAME: str = ""
    AWS_ENDPOINT: str = "https://s3.amazonaws.com"

    # Google OAuth configuration (ID Token verification)
    GOOGLE_CLIENT_ID: str = ""

    # Frontend URL configuration
    FRONTEND_URL: str = "http://localhost:3000"
    PASSWORD_RESET_URL_TEMPLATE: str = "{frontend_url}/reset-password?token={token}"

    # Verification code configuration
    VERIFICATION_CODE_LENGTH: int = 6
    VERIFICATION_CODE_EXPIRE_SECONDS: int = 300  # 5 minutes
    VERIFICATION_CODE_COOLDOWN_SECONDS: int = 60  # 60 seconds cooldown

    # Password reset configuration
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"  # Optional, specify encoding

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # SECURITY: Validate SECRET_KEY in production
        if self.ENV == "production" and len(self.SECRET_KEY) < 32:
            raise ValueError(
                "SECURITY ERROR: SECRET_KEY must be at least 32 characters long in production! "
                'Generate a secure key: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # SECURITY: Warn about excessive token lifetimes in production
        if self.ENV == "production":
            if self.ACCESS_TOKEN_EXPIRE_MINUTES > 120:
                import logging

                logging.getLogger(__name__).warning(
                    "SECURITY WARNING: ACCESS_TOKEN_EXPIRE_MINUTES=%d is too long for production. "
                    "Recommended: 30-60 minutes.",
                    self.ACCESS_TOKEN_EXPIRE_MINUTES,
                )
            if self.REFRESH_TOKEN_EXPIRE_DAYS > 30:
                import logging

                logging.getLogger(__name__).warning(
                    "SECURITY WARNING: REFRESH_TOKEN_EXPIRE_DAYS=%d is too long for production. "
                    "Recommended: 7-30 days.",
                    self.REFRESH_TOKEN_EXPIRE_DAYS,
                )

        # Now set Celery URLs after all attributes are loaded from env
        if self.REDIS_PASSWORD:
            redis_url = (
                f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
            )
        else:
            redis_url = f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        self.CELERY_BROKER_URL = redis_url
        self.CELERY_RESULT_BACKEND = redis_url


settings = Settings()
