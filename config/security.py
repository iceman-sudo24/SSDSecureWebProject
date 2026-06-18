"""
Security utilities and middleware for the Secure Microservice Web Application.

Implements:
- Security headers middleware (OWASP A05)
- CSRF failure view (OWASP A08)
- Custom DRF exception handler (safe error handling, OWASP A05)
- Service-to-service authentication (trust boundary enforcement)
"""

import logging
import hmac
from django.http import HttpResponseForbidden
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework import status

logger = logging.getLogger("django")


class SecurityHeadersMiddleware:
    """
    Middleware to inject security headers into all HTTP responses.
    
    Headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    Permissions-Policy, Content-Security-Policy, Cache-Control for sensitive pages.
    
    Mapped to: OWASP A05, ASVS V14.4
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self';"
        )
        
        if request.path.startswith(("/auth/", "/audit/", "/api/")):
            response["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"
        
        return response


def csrf_failure_view(request, reason=""):
    """
    Custom CSRF failure view. Returns safe error without exposing details.
    Mapped to: OWASP A08, ASVS V3.5
    """
    logger.warning(
        "CSRF failure: path=%s, reason=%s, ip=%s",
        request.path, reason, request.META.get("REMOTE_ADDR", "unknown"),
    )
    return HttpResponseForbidden(
        "<h1>403 Forbidden</h1>"
        "<p>CSRF verification failed. Please ensure cookies are enabled.</p>"
    )


def custom_exception_handler(exc, context):
    """
    Custom DRF exception handler preventing information disclosure.
    In production, replaces detailed errors with generic messages.
    Mapped to: OWASP A05, ASVS V7.4, NIST SSDF PW.4
    """
    response = exception_handler(exc, context)
    
    if response is not None:
        if not settings.DEBUG:
            if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
                response.data = {
                    "error": "An internal server error occurred.",
                    "detail": "Please contact support if the problem persists.",
                }
            elif response.status_code == status.HTTP_400_BAD_REQUEST:
                response.data = {
                    "error": "Invalid request.",
                    "detail": response.data if isinstance(response.data, dict) else "Invalid input provided.",
                }
        
        logger.error(
            "API Exception: %s - %s - view=%s - user=%s",
            type(exc).__name__, str(exc),
            context.get("view", "unknown"),
            getattr(context.get("request"), "user", "anonymous"),
        )
    
    return response


def verify_service_token(request):
    """
    Verify service-to-service authentication token.
    Uses constant-time comparison to prevent timing attacks.
    Mapped to: OWASP A01, ASVS V4.1
    """
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    
    if not auth_header.startswith("Bearer "):
        return False
    
    token = auth_header[7:]
    expected_token = getattr(settings, "SERVICE_AUTH_TOKEN", "")
    
    if not expected_token or expected_token == "change-me-in-production":  # nosec B105 — sentinel check, not a password
        logger.error("SERVICE_AUTH_TOKEN is not configured properly!")
        return False
    
    return hmac.compare_digest(token, expected_token)