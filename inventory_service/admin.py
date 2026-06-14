"""
Django Admin configuration for the Inventory Service.

InventoryAuditLog is fully read-only in admin — no add/change/delete allowed.
This prevents tampering with the audit trail via the admin interface.

Maps to:
- OWASP A09:2021 - Security Logging and Monitoring Failures (immutable audit trail)
- OWASP A01:2021 - Broken Access Control (admin-only access)
"""

from django.contrib import admin

from inventory_service.models import Category, InventoryAuditLog, InventoryItem


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Admin configuration for Category model."""

    list_display = ("name", "description", "created_at")
    search_fields = ("name", "description")
    ordering = ("name",)
    readonly_fields = ("id", "created_at")


@admin.register(InventoryItem)
class InventoryItemAdmin(admin.ModelAdmin):
    """
    Admin configuration for InventoryItem model.

    raw_id_fields avoids loading all users/categories in a dropdown
    (performance + security — prevents large querysets in admin).
    """

    list_display = (
        "name",
        "sku",
        "owner",
        "category",
        "quantity",
        "price",
        "status",
        "created_at",
    )
    list_filter = ("status", "category")
    search_fields = ("name", "sku", "owner__username")
    # raw_id_fields avoids loading all users/categories in a dropdown (performance + security)
    raw_id_fields = ("owner", "category")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("-created_at",)


@admin.register(InventoryAuditLog)
class InventoryAuditLogAdmin(admin.ModelAdmin):
    """
    Read-only admin view for the inventory audit log.

    Prevents administrators from modifying or deleting audit records,
    preserving the integrity of the audit trail.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """

    list_display = (
        "timestamp",
        "action",
        "item_name_snapshot",
        "username_snapshot",
        "field_changed",
        "ip_address",
    )
    list_filter = ("action", "timestamp")
    search_fields = ("username_snapshot", "item_name_snapshot", "ip_address")
    readonly_fields = (
        "id",
        "item",
        "item_name_snapshot",
        "user",
        "username_snapshot",
        "action",
        "field_changed",
        "old_value",
        "new_value",
        "ip_address",
        "timestamp",
    )
    ordering = ("-timestamp",)

    def has_add_permission(self, request):
        """Audit logs cannot be created via admin."""
        return False

    def has_change_permission(self, request, obj=None):
        """Audit logs cannot be modified via admin."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit logs cannot be deleted via admin."""
        return False