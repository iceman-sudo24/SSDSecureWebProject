"""
Audit logging utility for the Secure Microservice Web Application.

Provides a centralized function for logging audit events across all microservices.
All services (auth, inventory, audit) use log_audit_event() to record actions.

Security controls:
- Log message sanitization prevents sensitive data leakage (OWASP A09)
- Passwords, tokens, secrets, API keys, and credit card numbers are redacted
- Details field truncated to 1000 chars max
- Graceful error handling — audit failure must NOT crash the application
- Lazy imports to avoid circular dependencies

Maps to:
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V1.2 - Architecture (audit trail)
- ASVS V1.3 - Security Logging
- ASVS V1.4 - Log Protection
"""

import re
import logging

from django.db import transaction

logger = logging.getLogger("audit")


# =============================================================================
# Sanitization
# =============================================================================

# Patterns that match sensitive data in log messages
_SENSITIVE_PATTERNS = [
    (re.compile(r"password\s*=\s*\S+", re.IGNORECASE), "password=[REDACTED]"),
    (re.compile(r"token\s*=\s*\S+", re.IGNORECASE), "token=[REDACTED]"),
    (re.compile(r"secret\s*=\s*\S+", re.IGNORECASE), "secret=[REDACTED]"),
    (re.compile(r"api_key\s*=\s*\S+", re.IGNORECASE), "api_key=[REDACTED]"),
    (re.compile(r"credit.?card\s*=\s*\S+", re.IGNORECASE), "credit_card=[REDACTED]"),
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "[REDACTED_CARD]"),
]

# Maximum length for log details
_MAX_DETAILS_LENGTH = 1000


def _sanitize_log_message(message):
    """
    Sanitize a log message to remove sensitive data.

    Replaces patterns matching passwords, tokens, secrets, API keys,
    and credit card numbers with [REDACTED].

    Truncates the result to _MAX_DETAILS_LENGTH characters.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.4 - Log Protection

    Args:
        message (str): The raw log message to sanitize.

    Returns:
        str: The sanitized message with sensitive data redacted.
    """
    if not message:
        return ""

    sanitized = message
    for pattern, replacement in _SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    # Truncate to max length
    if len(sanitized) > _MAX_DETAILS_LENGTH:
        sanitized = sanitized[:_MAX_DETAILS_LENGTH] + "...[TRUNCATED]"

    return sanitized


# =============================================================================
# Audit Event Logging
# =============================================================================


def log_audit_event(
    user,
    action,
    service,
    ip_address=None,
    details="",
    resource_type="",
    resource_id="",
):
    """
    Log an audit event to the central audit log.

    This is the primary function used by all microservices to record
    significant user actions. It creates an AuditLog entry and also
    logs to the Python logging system.

    Security features:
    - Details are sanitized before storage (OWASP A09)
    - Graceful error handling — audit failure must NOT crash the app
    - Lazy imports to avoid circular dependencies

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)
    - ASVS V1.3 - Security Logging

    Args:
        user: The user who performed the action (can be None for anonymous).
        action (str): The action type (from AuditLog.Action choices).
        service (str): The source microservice name.
        ip_address (str, optional): Client IP address.
        details (str, optional): Additional context (will be sanitized).
        resource_type (str, optional): Type of resource acted upon.
        resource_id (str, optional): ID of the resource acted upon.

    Example:
        >>> from audit_service.utils import log_audit_event
        >>> log_audit_event(
        ...     user=request.user,
        ...     action="USER_LOGIN",
        ...     service="auth_service",
        ...     ip_address="192.168.1.1",
        ...     details="Successful login",
        ... )
    """
    try:
        # Lazy import to avoid circular imports
        from audit_service.models import AuditLog

        # Sanitize details before storage
        sanitized_details = _sanitize_log_message(details)

        # Create audit log entry within a transaction
        with transaction.atomic():
            AuditLog.objects.create(
                user=user,
                action=action,
                service=service,
                ip_address=ip_address,
                details=sanitized_details,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else "",
            )

        # Also log to Python logging system
        username = user.username if user else "anonymous"
        logger.info(
            "AUDIT: %s | %s | %s | %s | %s",
            action,
            service,
            username,
            ip_address or "N/A",
            sanitized_details[:200] if sanitized_details else "",
        )

    except Exception as e:
        # Audit failure must NOT crash the application
        # Log the error but continue
        logger.error(
            "Failed to create audit log entry: %s | action=%s, service=%s",
            str(e),
            action,
            service,
        )


# =============================================================================
# Audit Summary
# =============================================================================


def get_audit_summary(user=None, days=7):
    """
    Get a summary of audit events for a given period.

    Uses ORM aggregation (no raw SQL) for security and portability.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)

    Args:
        user: Optional user to filter by. If None, returns summary for all users.
        days (int): Number of days to look back. Defaults to 7.

    Returns:
        dict: Summary with keys:
            - period_days (int): The period in days.
            - total_events (int): Total number of events.
            - events_by_action (dict): Count of events per action type.
    """
    from datetime import timedelta
    from django.utils import timezone
    from django.db.models import Count

    try:
        from audit_service.models import AuditLog

        cutoff = timezone.now() - timedelta(days=days)
        queryset = AuditLog.objects.filter(timestamp__gte=cutoff)

        if user:
            queryset = queryset.filter(user=user)

        total_events = queryset.count()
        events_by_action = dict(
            queryset.values_list("action")
            .annotate(count=Count("id"))
            .order_by("-count")
        )

        return {
            "period_days": days,
            "total_events": total_events,
            "events_by_action": events_by_action,
        }

    except Exception as e:
        logger.error("Failed to generate audit summary: %s", str(e))
        return {
            "period_days": days,
            "total_events": 0,
            "events_by_action": {},
        }