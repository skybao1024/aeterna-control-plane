"""
Client-side Swagger UI Configuration File
Dedicated to client API documentation
"""

from typing import Any, Dict

from app.core.config import settings

# Client Swagger UI Configuration
CLIENT_SWAGGER_UI_PARAMETERS = {
    "deepLinking": True,
    "displayRequestDuration": True,
    "docExpansion": "list",  # Expand tags but not operations
    "operationsSorter": "alpha",  # Sort alphabetically
    "filter": True,
    "tryItOutEnabled": True,
}

# Client OpenAPI Metadata Configuration
CLIENT_OPENAPI_INFO = {
    "title": f"{settings.PROJECT_NAME} - Client API",
    "description": f"""
# Aeterna Client API

This API is used by Aeterna desktop clients. It only manages accounts,
registered devices, heartbeat state, contacts, notifications, and delayed
recovery coordination.

## Data boundary

- Vault contents, messages, media, and attachments must never be uploaded.
- Master passwords, emergency recovery codes, and vault data keys must never be uploaded.
- New endpoints must be reviewed against this boundary before registration.

The currently registered routes are framework foundations. Product endpoints
will be added only with their domain services, migrations, tests, and audit rules.

## Response format

All API responses follow a unified format:

```json
{{
    "code": 200,
    "message": "Operation successful",
    "data": {{}}
}}
```

## Environment Information

- **Current Environment**: {settings.ENV}
- **API Version**: v1
- **Documentation Type**: Client API
    """,
    "version": "1.0.0",
    "contact": {"name": "Aeterna Operations", "email": settings.ADMIN_EMAIL},
}

# Client OpenAPI Tags Configuration
CLIENT_OPENAPI_TAGS = [
    {
        "name": "client-config",
        "description": "Health and safe client configuration interfaces",
    },
    {
        "name": "client-auth",
        "description": "Desktop client account authentication interfaces",
    },
]


def get_client_openapi_config() -> Dict[str, Any]:
    """
    Get client OpenAPI configuration
    """
    return {
        **CLIENT_OPENAPI_INFO,
        "openapi": "3.0.2",
        "tags": CLIENT_OPENAPI_TAGS,
    }
