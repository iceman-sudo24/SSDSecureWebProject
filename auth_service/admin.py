"""
Admin configuration for the Authentication Service.

Provides admin interface for:
- User management with RBAC role display
- UserProfile management inline with User

Security controls:
- Read-only fields for timestamps and IP (prevents tampering)
- Role displayed in list view for quick RBAC oversight

Maps to:
- OWASP A01:2021 - Broken Access Control (admin oversight)
- OWASP A09:2021 - Security Logging and Monitoring Failures
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from auth_service.models import User, UserProfile


class UserProfileInline(admin.StackedInline):
    """
    Inline admin for UserProfile.
    Allows editing profile fields directly from the User admin page.
    """

    model = UserProfile
    can_delete = False
    verbose_name_plural = "Profile"
    fk_name = "user"
    fields = ("bio", "organization", "avatar")


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom User admin with RBAC role and profile inline.

    Extends Django's BaseUserAdmin to add:
    - role field for RBAC visibility
    - phone_number field
    - last_login_ip for security monitoring
    - Timestamps as read-only

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """

    # Add custom fields to the User admin
    fieldsets = BaseUserAdmin.fieldsets + (
        (
            "RBAC & Security",
            {
                "fields": ("role", "phone_number", "last_login_ip"),
            },
        ),
    )

    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        (
            "Additional Info",
            {
                "fields": ("email", "first_name", "last_name", "phone_number", "role"),
            },
        ),
    )

    # List display columns
    list_display = (
        "username",
        "email",
        "role",
        "is_active",
        "created_at",
    )

    # List filters for quick navigation
    list_filter = ("role", "is_active", "is_staff")

    # Search fields
    search_fields = ("username", "email", "first_name", "last_name")

    # Ordering
    ordering = ("-created_at",)

    # Read-only fields (timestamps and IP should not be manually editable)
    readonly_fields = ("created_at", "updated_at", "last_login_ip")

    # Include UserProfile inline
    inlines = [UserProfileInline]


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    Admin interface for UserProfile.
    Provides separate access to profile data if needed.
    """

    list_display = ("user", "organization")
    search_fields = ("user__username", "organization")
    readonly_fields = ("user",)