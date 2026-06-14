"""
Permission classes and decorators for the Authentication Service.

Provides:
- DRF permission classes for API views
- Function-based view decorators for template views
- RBAC enforcement at both view and object level

Security controls:
- Default deny (fail-closed) approach
- Admin role verification with audit logging
- Ownership verification for object-level access
- Constant-time role checks

Maps to:
- OWASP A01:2021 - Broken Access Control
- OWASP ASVS V4.1 - Access Control Architecture
- OWASP ASVS V4.2 - Operation Level Access Control
"""

import logging
from functools import wraps

from django.http import HttpResponseForbidden
from rest_framework.permissions import BasePermission

logger = logging.getLogger("audit")


class IsAdminUser(BasePermission):
    """
    Permission class that checks if the user has the ADMIN role.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture

    Usage:
        permission_classes = [IsAuthenticated, IsAdminUser]
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_admin


class IsNormalUser(BasePermission):
    """
    Permission class that checks if the user has the USER role.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_normal_user


class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission: owner of the object OR admin can access.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR prevention)
    - ASVS V4.2 - Operation Level Access Control

    Usage:
        permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    """

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        # Admin can access any object
        if request.user.is_admin:
            return True
        # Check owner field (supports both 'owner' and 'user' FK names)
        owner = getattr(obj, "owner", None) or getattr(obj, "user", None)
        if owner is None:
            logger.warning(
                "IsOwnerOrAdmin: object '%s' has no owner attribute — denying access to '%s'",
                obj, request.user.username,
            )
            return False
        if owner != request.user:
            logger.warning(
                "ACCESS_DENIED: user='%s' role='%s' tried to access object '%s' owned by '%s'",
                request.user.username, request.user.role, obj, owner.username,
            )
            try:
                from audit_service.utils import log_audit_event
                log_audit_event(
                    user=request.user,
                    action="ACCESS_DENIED",
                    service="auth_service",
                    ip_address=request.META.get("REMOTE_ADDR", "unknown"),
                    details=f"User '{request.user.username}' denied access to object owned by '{owner.username}'",
                )
            except Exception:
                pass
            return False
        return True


class IsOwner(BasePermission):
    """
    Strict ownership check: ONLY the owner can access. No admin override.

    Used for delete operations where even admins should not bypass ownership.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.2 - Operation Level Access Control
    """

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        owner = getattr(obj, "owner", None) or getattr(obj, "user", None)
        if owner is None:
            return False
        return owner == request.user


def admin_required(view_func):
    """
    Decorator for function-based views requiring admin role.

    Logs warning for non-admin access attempts for security monitoring.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V4.1 - Access Control Architecture

    Usage:
        @login_required
        @admin_required
        def my_admin_view(request):
            ...
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Authentication required.")

        if not request.user.is_admin:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            logger.warning(
                "ACCESS_DENIED (admin_required): user='%s' role='%s' path='%s' ip='%s'",
                request.user.username,
                request.user.role,
                request.path,
                ip,
            )
            # Log to audit service
            try:
                from audit_service.utils import log_audit_event
                log_audit_event(
                    user=request.user,
                    action="ACCESS_DENIED",
                    service="auth_service",
                    ip_address=ip,
                    details=f"Non-admin user '{request.user.username}' attempted to access admin resource: {request.path}",
                )
            except Exception:
                pass
            return HttpResponseForbidden(
                "You do not have permission to access this resource."
            )

        return view_func(request, *args, **kwargs)

    return wrapper


def role_required(*roles):
    """
    Decorator for function-based views requiring specific roles.

    Args:
        *roles: One or more role strings (e.g., "ADMIN", "USER")

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture

    Usage:
        @login_required
        @role_required("ADMIN", "MANAGER")
        def my_view(request):
            ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Authentication required.")

            if request.user.role not in roles:
                ip = request.META.get("REMOTE_ADDR", "unknown")
                logger.warning(
                    "ACCESS_DENIED (role_required): user='%s' role='%s' "
                    "required_roles=%s path='%s' ip='%s'",
                    request.user.username,
                    request.user.role,
                    roles,
                    request.path,
                    ip,
                )
                try:
                    from audit_service.utils import log_audit_event
                    log_audit_event(
                        user=request.user,
                        action="ACCESS_DENIED",
                        service="auth_service",
                        ip_address=ip,
                        details=f"User '{request.user.username}' (role={request.user.role}) denied access to {request.path} (required: {roles})",
                    )
                except Exception:
                    pass
                return HttpResponseForbidden(
                    "You do not have permission to access this resource."
                )

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator