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

Account verification and device binding use the public v1 protocol contract.
Every request is bounded, strictly parsed, versioned, and closed to unknown
members. Mailbox-control grants are short-lived, purpose-bound, and one-use.

## Response format

The account/device protocol returns closed success documents:

```json
{{
    "protocol_version": 1,
    "request_id": "00000000-0000-4000-8000-000000000001",
    "data": {{}}
}}
```

Failures return a stable nonlocalized `error.code`; they never include mailbox
addresses, OTPs, grants, signing material, provider responses, or stack traces.

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
        "name": "account-device-identity",
        "description": "Passwordless mailbox verification and signed device binding",
    },
    {
        "name": "contacts-email-notifications",
        "description": (
            "Signed contact consent, bounded notification templates, and "
            "transport-only email status"
        ),
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
