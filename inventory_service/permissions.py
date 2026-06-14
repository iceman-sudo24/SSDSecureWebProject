"""
DRF and decorator-based permission classes for the Inventory Service.

These permissions enforce object-level access control (IDOR prevention).
The key principle: a user may only act on items they own,
unless they hold the ADMIN role.

Maps to:
- OWASP A01:2021 - Broken Access Control (IDOR prevention)
- OWASP ASVS V4.2 - Operation Level Access Control
- OWASP ASVS V4.3 - Other Access Control Considerations
"""

import logging

from django.http import HttpResponseForbidden
from rest_framework.permissions import BasePermission, SAFE_METHODS

logger = logging.getLogger("django")


class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission: allow access only if the requesting user
    is the item's owner OR holds the ADMIN role.

    Used for: view, update operations (retrieve/partial_update/update).
    Default deny — if the object has no 'owner' attribute, access is denied.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR prevention)
    - ASVS V4.2 - Operation Level Access Control
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        if request.user.is_admin:
            return True

        owner = getattr(obj, "owner", None)
        if owner is None:
            logger.warning(
                "IsOwnerOrAdmin: object '%s' has no 'owner' attribute "
                "-- denying access to user '%s'",
                obj,
                request.user.username,
            )
            return False

        if obj.owner != request.user:
            logger.warning(
                "IDOR attempt: user '%s' tried to access item '%s' owned by '%s'",
                request.user.username,
                getattr(obj, "pk", "unknown"),
                obj.owner.username,
            )
            return False

        return True


class IsOwner(BasePermission):
    """
    Strict ownership permission — admin override NOT allowed.

    Used for: delete operations where even admins should not delete
    another user's items through the API without explicit intent.
    Template views use IsOwnerOrAdmin for delete with admin override.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.2 - Operation Level Access Control
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        owner = getattr(obj, "owner", None)
        if owner is None:
            return False
        return obj.owner == request.user


class IsAdminOrReadOnly(BasePermission):
    """
    Admins may perform any action; authenticated users have read-only access.

    Used for: Category management — all authenticated users can list
    categories, but only admins can create/update/delete them.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.1 - Access Control Architecture
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_admin


def owner_required(view_func):
    """
    Decorator for function-based views that enforces item ownership.

    Expects the view to receive 'item_id' as a kwarg and the item
    to be retrieved via get_object_or_404. The actual ownership check
    is performed inside each view for clarity, but this decorator
    provides an additional authentication gate.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - ASVS V4.2 - Operation Level Access Control
    """
    from django.contrib.auth.decorators import login_required
    return login_required(view_func)