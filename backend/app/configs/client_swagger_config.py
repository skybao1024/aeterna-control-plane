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
# Client API Service

This is the public API interface documentation for client applications.

## Functional Modules

### Demo Functions (Demo)
- Basic demonstration interfaces
- Function testing interfaces

### Configuration Management (Config)
- Client configuration retrieval
- System configuration queries

### Cloud Storage Service (AWS)
- File upload functionality
- S3 storage integration

## Technical Features

- 🚀 **High Performance**: Based on FastAPI async framework
- 📊 **Database**: PostgreSQL + SQLAlchemy ORM
- 🎯 **Cache**: Redis cache system
- ☁️ **Cloud Storage**: AWS S3 integration
- 📝 **Documentation**: Auto-generated OpenAPI documentation
- ⚡ **Async**: Full async processing for improved performance

## Response Format

All API responses follow a unified format:

```json
{{
    "success": true,
    "message": "Operation successful",
    "data": {{}},
    "code": 200
}}
```

## Environment Information

- **Current Environment**: {settings.ENV}
- **API Version**: v1
- **Documentation Type**: Client API
    """,
    "version": "1.0.0",
    "contact": {
        "name": "Development Team",
        "email": settings.ADMIN_EMAIL,
    },
    "license_info": {
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
}

# Client OpenAPI Tags Configuration
CLIENT_OPENAPI_TAGS = [
    {
        "name": "client-demo",
        "description": "Client demonstration interfaces",
        "externalDocs": {
            "description": "Learn more",
            "url": "https://fastapi.tiangolo.com/",
        },
    },
    {
        "name": "client-config",
        "description": "Client configuration interfaces",
        "externalDocs": {
            "description": "Configuration documentation",
            "url": "https://fastapi.tiangolo.com/tutorial/",
        },
    },
    {
        "name": "client-aws",
        "description": "Client cloud storage interfaces",
        "externalDocs": {
            "description": "AWS S3 documentation",
            "url": "https://docs.aws.amazon.com/s3/",
        },
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
