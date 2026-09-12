"""
OpenAPI JSON export routes
Provide standalone API documentation JSON download functionality for importing to other API management tools
"""

import json

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from app.configs.docs_apps import create_backoffice_app, create_client_app

router = APIRouter(prefix="/api-docs", tags=["API Documentation Export"])


@router.get(
    "/client.json",
    summary="Client API Documentation JSON",
    description="Download client API OpenAPI JSON documentation, can be imported to Postman, Insomnia, etc.",
)
async def get_client_openapi_json():
    """
    Get client API OpenAPI JSON documentation
    For importing to Postman, Insomnia, ApiPost and other API management tools
    """
    client_app = create_client_app()
    openapi_schema = client_app.openapi()

    # Set response headers, prompt download
    headers = {
        "Content-Disposition": "attachment; filename=client-api.json",
        "Content-Type": "application/json",
    }

    return JSONResponse(content=openapi_schema, headers=headers)


@router.get(
    "/backoffice.json",
    summary="Backoffice API Documentation JSON",
    description="Download backoffice API OpenAPI JSON documentation, includes JWT authentication configuration",
)
async def get_backoffice_openapi_json():
    """
    Get backoffice API OpenAPI JSON documentation
    Includes complete JWT authentication configuration for importing to API management tools
    """
    backoffice_app = create_backoffice_app()
    openapi_schema = backoffice_app.openapi()

    # Set response headers, prompt download
    headers = {
        "Content-Disposition": "attachment; filename=backoffice-api.json",
        "Content-Type": "application/json",
    }

    return JSONResponse(content=openapi_schema, headers=headers)


@router.get("/", summary="API Documentation Export Guide")
async def api_docs_info():
    """
    API documentation export functionality guide
    """
    return {
        "message": "FastAPI Template - API Documentation Export",
        "description": "Provide OpenAPI JSON format API documentation for importing to various API management tools",
        "downloads": {
            "client": {
                "url": "/api-docs/client.json",
                "description": "Client API documentation (no authentication, includes AWS features)",
                "filename": "client-api.json",
                "features": [
                    "Demo endpoints",
                    "Configuration management",
                    "AWS S3 upload",
                ],
            },
            "backoffice": {
                "url": "/api-docs/backoffice.json",
                "description": "Backoffice API documentation (includes JWT authentication)",
                "filename": "backoffice-api.json",
                "features": [
                    "Authentication management",
                    "Admin management",
                    "AWS management",
                    "Permission control",
                ],
            },
        },
        "import_guides": {
            "postman": "In Postman, select Import > Upload Files to import JSON file",
            "insomnia": "In Insomnia, select Import/Export > Import Data to import JSON file",
            "apipost": "In ApiPost, select Import > OpenAPI to import JSON file",
            "swagger_editor": "In Swagger Editor, select File > Import File to import JSON file",
            "apifox": "In Apifox, select Import > From URL/File > OpenAPI format",
        },
        "authentication": {
            "client": "Client API requires no authentication, use directly",
            "backoffice": "Backoffice API requires JWT authentication, configure Bearer Token authentication in tool after import",
        },
        "technical_info": {
            "openapi_version": "3.0.2",
            "framework": "FastAPI",
            "authentication": "JWT Bearer Token",
            "response_format": "Unified ApiResponse format",
        },
    }
