"""
Security Headers Middleware

Adds security headers to all HTTP responses to protect against common web vulnerabilities.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Headers added:
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking attacks
    - X-XSS-Protection: Enables browser XSS protection (legacy browsers)
    - Strict-Transport-Security: Forces HTTPS (production only)
    - Content-Security-Policy: Restricts resource loading
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Controls browser features
    """

    def __init__(self, app, enable_hsts: bool = False, is_production: bool = False):
        """
        Initialize security headers middleware.

        Args:
            app: The FastAPI application
            enable_hsts: Enable HSTS header (only in production with HTTPS)
            is_production: Whether running in production (tighter CSP)
        """
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.is_production = is_production

    async def dispatch(self, request: Request, call_next):
        """Add security headers to the response."""
        response: Response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking - deny embedding in iframes
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS - Force HTTPS (only enable in production with valid SSL)
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Content Security Policy - restrict resource loading
        # Production: strict CSP without unsafe-inline/unsafe-eval
        # Dev/Preview: relaxed CSP to allow Swagger UI (cdn.jsdelivr.net)
        if self.is_production:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://cdn.jsdelivr.net; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            )

        # Referrer Policy - control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy - control browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        # Remove server header to avoid information disclosure
        if "Server" in response.headers:
            del response.headers["Server"]

        return response
