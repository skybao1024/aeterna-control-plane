"""
Separated FastAPI application factories
Provides independent documentation applications for Client and Backoffice
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from app.configs.backoffice_swagger_config import (
    BACKOFFICE_OPENAPI_INFO, BACKOFFICE_OPENAPI_TAGS,
    BACKOFFICE_SECURITY_SCHEMES, BACKOFFICE_SWAGGER_UI_PARAMETERS)
from app.configs.client_swagger_config import (CLIENT_OPENAPI_INFO,
                                               CLIENT_OPENAPI_TAGS,
                                               CLIENT_SWAGGER_UI_PARAMETERS)
from app.core.config import settings

# Set CORS origins based on environment
ALLOWED_ORIGINS = (
    ["*"]
    if settings.ENV == "development" or settings.ENV == "preview"
    else ["*"]  # TODO: replace with production domain
)


def create_client_app() -> FastAPI:
    """
    Create Client API documentation application
    """
    app = FastAPI(
        title=CLIENT_OPENAPI_INFO["title"],
        description=CLIENT_OPENAPI_INFO["description"],
        version=CLIENT_OPENAPI_INFO["version"],
        contact=CLIENT_OPENAPI_INFO["contact"],
        license_info=CLIENT_OPENAPI_INFO["license_info"],
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=CLIENT_OPENAPI_TAGS,
        swagger_ui_parameters=CLIENT_SWAGGER_UI_PARAMETERS,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register client routes using route registry
    from app.route.router_registry import get_client_routes, register_routes

    register_routes(app, get_client_routes())

    return app


def create_backoffice_app() -> FastAPI:
    """
    Create Backoffice management API documentation application
    """
    app = FastAPI(
        title=BACKOFFICE_OPENAPI_INFO["title"],
        description=BACKOFFICE_OPENAPI_INFO["description"],
        version=BACKOFFICE_OPENAPI_INFO["version"],
        contact=BACKOFFICE_OPENAPI_INFO["contact"],
        license_info=BACKOFFICE_OPENAPI_INFO["license_info"],
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=BACKOFFICE_OPENAPI_TAGS,
        swagger_ui_parameters=BACKOFFICE_SWAGGER_UI_PARAMETERS,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register backoffice routes using route registry
    from app.route.router_registry import (get_backoffice_routes,
                                           register_routes)

    register_routes(app, get_backoffice_routes())

    # Customize OpenAPI schema to add JWT authentication configuration
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=BACKOFFICE_OPENAPI_INFO["title"],
            version=BACKOFFICE_OPENAPI_INFO["version"],
            description=BACKOFFICE_OPENAPI_INFO["description"],
            routes=app.routes,
            openapi_version="3.0.2",
            contact=BACKOFFICE_OPENAPI_INFO["contact"],
            license_info=BACKOFFICE_OPENAPI_INFO["license_info"],
        )

        # Add JWT authentication configuration
        openapi_schema["components"]["securitySchemes"] = BACKOFFICE_SECURITY_SCHEMES

        # Add security configuration to endpoints requiring authentication (except login endpoint)
        for path, methods in openapi_schema["paths"].items():
            if (
                "/backoffice/auth/login" not in path
            ):  # Login endpoint doesn't require authentication
                for method_name, method_info in methods.items():
                    if method_name in ["get", "post", "put", "delete", "patch"]:
                        method_info["security"] = [{"BearerAuth": []}]

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app
