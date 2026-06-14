"""
Central Audit Log model for the Secure Microservice Web Application.

Provides a unified audit trail across all microservices (auth, inventory, audit).
Every significant user action is recorded with user, action, service, IP, and details.

Security controls:
- UUID primary key prevents ID enumeration (OWASP A01)
- Username snapshot preserved even if user is deleted (OWASP A09)
- Details field must NOT contain passwords/tokens (sanitized in utils.py)
- SET_NULL on user FK ensures audit records survive user deletion
- Comprehensive indexing for efficient querying
- save() override auto-captures username snapshot

Maps to:
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V1.2 - Architecture (audit trail)
- ASVS V1.3 - Security Logging
- ASVS V1.4 - Log Protection
"""

import uuid
import logging

from django.conf import settings
from django.db import models

logger = logging.getLogger("django")


# =============================================================================
# AuditLog Model
# =============================================================================


class AuditLog(models.Model):
    """
    Central audit log recording all significant actions across microservices.

    Each log entry captures:
    - Who performed the action (user + username snapshot)
    - What action was performed (action type)
    - Which service recorded it (auth_service, inventory_service, audit_service)
    - Where it came from (IP address)
    - Additional context (details, resource type/id)
    - When it happened (timestamp)

    Security features:
    - UUID PK prevents ID enumeration (OWASP A01)
    - Username snapshot preserved even if user is deleted (OWASP A09)
    - SET_NULL on user FK ensures audit records survive user deletion
    - Details field sanitized to prevent sensitive data leakage (OWASP A09)
    - Comprehensive indexing for efficient querying

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)
    - ASVS V1.3 - Security Logging
    - ASVS V1.4 - Log Protection
    """

    class Action(models.TextChoices):
        """Audit action types covering all microservices."""
        # Auth service actions
        USER_REGISTERED = "USER_REGISTERED", "User Registered"
        USER_LOGIN = "USER_LOGIN", "User Login"
        USER_LOGOUT = "USER_LOGOUT", "User Logout"
        PASSWORD_CHANGED = "PASSWORD_CHANGED", "Password Changed"
        PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Password Reset Requested"
        LOGIN_FAILED = "LOGIN_FAILED", "Login Failed"
        PROFILE_UPDATED = "PROFILE_UPDATED", "Profile Updated"

        # Inventory service actions
        INVENTORY_CREATED = "INVENTORY_CREATED", "Inventory Created"
        INVENTORY_UPDATED = "INVENTORY_UPDATED", "Inventory Updated"
        INVENTORY_DELETED = "INVENTORY_DELETED", "Inventory Deleted"
        INVENTORY_VIEWED = "INVENTORY_VIEWED", "Inventory Viewed"

        # Security actions
        ACCESS_DENIED = "ACCESS_DENIED", "Access Denied"
        IDOR_ATTEMPT = "IDOR_ATTEMPT", "IDOR Attempt"

        # Admin actions
        USER_ROLE_CHANGED = "USER_ROLE_CHANGED", "User Role Changed"
        USER_DEACTIVATED = "USER_DEACTIVATED", "User Deactivated"
        USER_ACTIVATED = "USER_ACTIVATED", "User Activated"

    # UUID primary key prevents ID enumeration
    # Maps to OWASP A01:2021 - Broken Access Control
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    # User who performed the action (SET_NULL so audit records survive user deletion)
    # Maps to OWASP A09:2021 - Security Logging and Monitoring Failures
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text="User who performed the action.",
    )

    # Username snapshot preserved even if user is deleted
    # Maps to OWASP A09:2021 - Security Logging and Monitoring Failures
    username = models.CharField(
        max_length=150,
        blank=True,
        help_text="Username snapshot at the time of the event.",
    )

    # Action type
    action = models.CharField(
        max_length=30,
        choices=Action.choices,
        db_index=True,
        help_text="Type of action performed.",
    )

    # Source microservice
    # Maps to OWASP A09:2021 - Security Logging and Monitoring Failures
    service = models.CharField(
        max_length=50,
        db_index=True,
        help_text="Source microservice (auth_service, inventory_service, audit_service).",
    )

    # Client IP address
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Client IP address at the time of the event.",
    )

    # Additional context (MUST NOT contain passwords/tokens — sanitized in utils.py)
    # Maps to OWASP A09:2021 - Security Logging and Monitoring Failures
    details = models.TextField(
        max_length=1000,
        blank=True,
        help_text="Additional context. Must NOT contain passwords or tokens.",
    )

    # Resource identification
    resource_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="Type of resource acted upon (e.g., 'InventoryItem', 'User').",
    )
    resource_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="ID of the resource acted upon.",
    )

    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp when the event was recorded.",
    )

    class Meta:
        db_table = "audit_log"
        ordering = ["-timestamp"]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        indexes = [
            models.Index(fields=["user", "timestamp"], name="audit_user_ts_idx"),
            models.Index(fields=["action", "timestamp"], name="audit_action_ts_idx"),
            models.Index(fields=["service", "timestamp"], name="audit_service_ts_idx"),
            models.Index(fields=["ip_address"], name="audit_ip_idx"),
        ]

    def __str__(self):
        return (
            f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] "
            f"{self.action} by {self.username} from {self.service}"
        )

    def save(self, *args, **kwargs):
        """
        Auto-capture username snapshot from user on first save.

        This ensures the username is preserved even if the user is later deleted.
        Maps to OWASP A09:2021 - Security Logging and Monitoring Failures.
        """
        if not self.username and self.user:
            self.username = self.user.username
        super().save(*args, **kwargs)