"""
Permission classes and decorators for the Audit Logging Service.

Security controls:
- IsAdminOnly: REST API permission class for admin-only endpoints
- admin_only: Function-based view decorator for admin-only access
- Both log warnings for unauthorized access attempts (OWASP A01)
- Default deny: non-admin users are rejected

Maps to:
- OWASP A01:2021 - Broken Access Control
- ASVS V4.1 - Access Control Architecture
- ASVS V4.2 - Operation Level Access Control
"""

import logging
from functools import wraps

from django.http import HttpResponseForbidden
from rest_framework.permissions import BasePermission

logger = logging.getLogger("django")


class IsAdminOnly(BasePermission):
    """
    REST API permission class that allows access only to admin users.

    Used on audit service API endpoints to ensure only administrators
    can query audit logs and summaries.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture
    """

    def has_permission(self, request, view):
        """
        Check if the requesting user is an authenticated admin.

        Logs a warning if a non-admin user attempts to access
        an admin-only endpoint.
        """
        if not request.user or not request.user.is_authenticated:
            return False

        if not request.user.is_admin:
            logger.warning(
                "Unauthorized audit API access attempt: user='%s' (role=%s) IP=%s",
                request.user.username,
                request.user.role,
                _get_client_ip(request),
            )
            return False

        return True


def _get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def admin_only(view_func):
    """
    Decorator for function-based views that restricts access to admin users.

    Checks authentication first, then verifies admin role.
    Returns HttpResponseForbidden if the user is not an admin.
    Logs warnings for unauthorized access attempts.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture

    Usage:
        @login_required
        @admin_only
        def my_view(request):
            ...
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check authentication
        if not request.user.is_authenticated:
            logger.warning(
                "Unauthenticated access attempt to admin-only view: %s",
                view_func.__name__,
            )
            return HttpResponseForbidden(
                "You do not have permission to access this page."
            )

        # Check admin role
        if not request.user.is_admin:
            logger.warning(
                "Non-admin access attempt to admin-only view: user='%s' (role=%s) view='%s' IP=%s",
                request.user.username,
                request.user.role,
                view_func.__name__,
                _get_client_ip(request),
            )
            return HttpResponseForbidden(
                "You do not have permission to access this page."
            )

        return view_func(request, *args, **kwargs)

    return _wrapped_view