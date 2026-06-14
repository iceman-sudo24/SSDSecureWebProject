"""
Django admin configuration for the AuditLog model.

Security controls:
- AuditLogAdmin is fully read-only (no add/change/delete permissions)
- Prevents accidental modification of audit records
- Provides filtering and search for efficient log review

Maps to:
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V1.2 - Architecture (audit trail)
"""

from django.contrib import admin
from audit_service.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """
    Read-only admin interface for audit logs.

    All add/change/delete permissions are disabled to prevent
    accidental or malicious modification of audit records.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)
    """

    # Display columns in the list view
    list_display = [
        "timestamp",
        "action",
        "username",
        "service",
        "ip_address",
        "resource_type",
        "resource_id",
    ]

    # Filter sidebar
    list_filter = ["action", "service", "timestamp"]

    # Date hierarchy for quick navigation
    date_hierarchy = "timestamp"

    # Search fields
    search_fields = ["username", "details", "ip_address", "resource_id"]

    # All fields are read-only
    readonly_fields = [
        "id",
        "user",
        "username",
        "action",
        "service",
        "ip_address",
        "details",
        "resource_type",
        "resource_id",
        "timestamp",
    ]

    # Prevent adding audit logs through admin
    def has_add_permission(self, request):
        """Audit logs cannot be created through the admin interface."""
        return False

    # Prevent modifying audit logs through admin
    def has_change_permission(self, request, obj=None):
        """Audit logs cannot be modified through the admin interface."""
        return False

    # Prevent deleting audit logs through admin
    def has_delete_permission(self, request, obj=None):
        """Audit logs cannot be deleted through the admin interface."""
        return False

    # Disable the "view on site" link
    def has_view_permission(self, request, obj=None):
        """Allow viewing audit logs (read-only)."""
        return request.user.is_authenticated and request.user.is_admin

    def get_queryset(self, request):
        """Only admins can view audit logs."""
        qs = super().get_queryset(request)
        if request.user.is_authenticated and request.user.is_admin:
            return qs
        return qs.none()