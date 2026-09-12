"""
Route registry
Centralized management of all route configurations to avoid duplication
"""

from typing import Dict, List

from app.core.config import settings


class RouteConfig:
    """Route configuration class"""

    def __init__(self, module_path: str, prefix: str, tags: List[str]):
        self.module_path = module_path
        self.prefix = prefix
        self.tags = tags


# Client route configuration
CLIENT_ROUTES = [
    RouteConfig(
        module_path="app.api.client.v1.auth",
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["client-auth"],
    ),
    RouteConfig(
        module_path="app.api.client.v1.demo",
        prefix=f"{settings.API_V1_STR}/demo",
        tags=["client-demo"],
    ),
    RouteConfig(
        module_path="app.api.client.v1.config",
        prefix=f"{settings.API_V1_STR}/config",
        tags=["client-config"],
    ),
    RouteConfig(
        module_path="app.api.client.v1.aws",
        prefix=f"{settings.API_V1_STR}/aws",
        tags=["client-aws"],
    ),
]

# Backoffice route configuration
BACKOFFICE_ROUTES = [
    RouteConfig(
        module_path="app.api.backoffice.v1.auth",
        prefix=f"{settings.API_V1_STR}/backoffice/auth",
        tags=["backoffice-auth"],
    ),
    RouteConfig(
        module_path="app.api.backoffice.v1.admin",
        prefix=f"{settings.API_V1_STR}/backoffice/admins",
        tags=["backoffice-admin"],
    ),
    RouteConfig(
        module_path="app.api.backoffice.v1.aws",
        prefix=f"{settings.API_V1_STR}/backoffice/aws",
        tags=["backoffice-aws"],
    ),
]

# Common route configuration (routes that are not client or backoffice specific)
COMMON_ROUTES = [
    RouteConfig(
        module_path="app.api.docs_export", prefix="", tags=["API Documentation Export"]
    ),
]


def register_routes(app, route_configs: List[RouteConfig]):
    """
    Dynamically register routes

    Args:
        app: FastAPI application instance
        route_configs: List of route configurations
    """
    for route_config in route_configs:
        # Dynamically import module
        module_parts = route_config.module_path.split(".")
        module_name = module_parts[-1]

        # Import module
        module = __import__(route_config.module_path, fromlist=[module_name])

        # Register route
        app.include_router(
            module.router, prefix=route_config.prefix, tags=route_config.tags
        )


def get_client_routes() -> List[RouteConfig]:
    """Get client route configuration"""
    return CLIENT_ROUTES


def get_backoffice_routes() -> List[RouteConfig]:
    """Get backoffice route configuration"""
    return BACKOFFICE_ROUTES


def get_common_routes() -> List[RouteConfig]:
    """Get common route configuration"""
    return COMMON_ROUTES


def get_all_routes() -> Dict[str, List[RouteConfig]]:
    """Get all route configurations"""
    return {
        "client": CLIENT_ROUTES,
        "backoffice": BACKOFFICE_ROUTES,
        "common": COMMON_ROUTES,
    }
