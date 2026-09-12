import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.common.log_consumer import consume_logs_forever
from app.configs.docs_apps import create_backoffice_app, create_client_app
from app.core.config import settings
from app.core.log_config import (is_master_process, setup_logging,
                                 shutdown_logging)
from app.db.base import close_db_engine
from app.exceptions.http_exceptions import APIException
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.schemas.response import ApiResponse
from app.services.common.redis import redis_client
from app.services.common.thread_pool import ThreadPoolService

# Route imports have been moved to centralized route registry


logger = logging.getLogger(__name__)

# Global thread pool service instance (for application lifecycle management)
_thread_pool_service: ThreadPoolService = None

# Set CORS origins based on environment
# SECURITY: In production, NEVER use ["*"] - specify exact domains
ALLOWED_ORIGINS = (
    ["*"]
    if settings.ENV == "development" or settings.ENV == "preview"
    else [
        settings.FRONTEND_URL,  # Use FRONTEND_URL from settings
        # Add additional production domains here:
        # "https://app.yourdomain.com",
        # "https://admin.yourdomain.com",
    ]
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    global _thread_pool_service

    # Execute on startup
    setup_logging()
    logger.info("Application starting up")

    # Initialize thread pool service
    _thread_pool_service = ThreadPoolService()

    # Log consumer thread (only start in master process to prevent duplication)
    if is_master_process():
        try:
            # Create a wrapper function to run async function in a thread
            def run_log_consumer():
                asyncio.run(consume_logs_forever())

            log_thread = threading.Thread(target=run_log_consumer, daemon=True)
            log_thread.start()
            logger.info("[LogConsumer] Log consumer thread started (master process)")
        except Exception as e:
            logger.warning(f"[LogConsumer] Failed to start log consumer thread: {e}")

    yield  # Application running period

    # Execute on shutdown
    if is_master_process():
        shutdown_logging()  # Close logging

    await close_db_engine()  # Clean up database engine
    await redis_client.close()  # Close Redis connection
    if _thread_pool_service:
        _thread_pool_service.shutdown()  # Close email thread pool
    logger.info("Application shutting down")


def create_app():
    app = FastAPI(
        lifespan=lifespan,
        title=settings.PROJECT_NAME,
        description="FastAPI Template - Unified Entry",
        version="1.0.0",
        docs_url=None,  # Disable default docs
        redoc_url=None,  # Disable default ReDoc
        openapi_url=None,  # Disable default OpenAPI
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,  # Should set specific domains in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # SECURITY: Add security headers middleware
    # Enable HSTS only in production with valid SSL certificate
    # Tighter CSP in production (no unsafe-inline/unsafe-eval)
    is_production = settings.ENV == "production"
    app.add_middleware(
        SecurityHeadersMiddleware,
        enable_hsts=is_production,
        is_production=is_production,
    )

    # SECURITY: Configure rate limiting to prevent abuse and brute-force attacks
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Provide documentation access guide in development environment, hide in production
    if settings.ENV in ["development", "preview"]:

        @app.get("/", tags=["Documentation Navigation"])
        async def swagger_navigation():
            """
            Development environment Swagger documentation navigation
            """
            return {
                "message": "FastAPI Template - Development Environment",
                "environment": settings.ENV,
                "documentation": {
                    "client_api": {
                        "swagger": "/client/docs",
                        "redoc": "/client/redoc",
                        "openapi": "/client/openapi.json",
                        "description": "Client API documentation (no authentication required)",
                    },
                    "backoffice_api": {
                        "swagger": "/backoffice/docs",
                        "redoc": "/backoffice/redoc",
                        "openapi": "/backoffice/openapi.json",
                        "description": "Backoffice API documentation (JWT authentication required)",
                    },
                },
                "api_exports": {
                    "client_json": "/api-docs/client.json",
                    "backoffice_json": "/api-docs/backoffice.json",
                    "info": "/api-docs/",
                },
                "health_check": "/api/v1/config/health",
            }

    # Use route registry to register all routes uniformly
    from app.route.router_registry import (get_backoffice_routes,
                                           get_client_routes,
                                           get_common_routes, register_routes)

    # Register client routes
    register_routes(app, get_client_routes())

    # Register backoffice routes
    register_routes(app, get_backoffice_routes())

    # Register common routes
    register_routes(app, get_common_routes())

    # Mount separated documentation applications
    client_docs_app = create_client_app()
    backoffice_docs_app = create_backoffice_app()

    app.mount("/client", client_docs_app)
    app.mount("/backoffice", backoffice_docs_app)

    @app.exception_handler(APIException)
    async def api_exception_handler(request: Request, exc: APIException):
        logger.error(
            f"API Exception: {exc.status_code} - {exc.code} - {exc.detail}",
            extra={"request": f"{request.method} {request.url}"},
        )
        return ApiResponse.failed(
            message=exc.detail,
            body_code=exc.code,  # Business error code
            http_code=exc.status_code,
            data=exc.data,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger.error(
            f"HTTP Exception: {exc.status_code} - {exc.detail}",
            extra={"request": f"{request.method} {request.url}"},
        )
        return ApiResponse.failed(
            message=exc.detail,
            body_code=exc.status_code,  # Fallback to HTTP status code
            http_code=exc.status_code,
            data=None,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        logger.warning(
            f"Validation Error: {exc.errors()}",
            extra={"request": f"{request.method} {request.url}"},
        )
        return ApiResponse.failed(
            message="Validation error",
            body_code=1001,
            http_code=status.HTTP_400_BAD_REQUEST,
            data=[
                {
                    "field": ".".join(
                        str(loc) for loc in err.get("loc", []) if loc != "body"
                    ),
                    "message": err.get("msg", "Invalid value"),
                }
                for err in exc.errors()
            ],
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(
            f"Unhandled Exception: {str(exc)}",
            extra={"request": f"{request.method} {request.url}"},
        )
        return ApiResponse.failed(
            message="Internal server error",
            body_code=1005,
            http_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return app
