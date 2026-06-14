"""
Serializers for the Audit Logging Service REST API.

Security controls:
- All fields are read-only (audit logs cannot be created/modified via API)
- No sensitive data exposed (passwords/tokens sanitized at storage time)
- Admin-only access enforced via IsAdminOnly permission

Maps to:
- OWASP A01:2021 - Broken Access Control
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V4.1 - Access Control Architecture
- ASVS V1.2 - Architecture (audit trail)
"""

from rest_framework import serializers
from audit_service.models import AuditLog
from audit_service.utils import get_audit_summary


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for individual audit log entries.

    Exposes all AuditLog fields in a structured format.
    All fields are read-only — audit logs cannot be modified via the API.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)
    """

    class Meta:
        model = AuditLog
        fields = [
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
        read_only_fields = fields


class AuditLogSummarySerializer(serializers.Serializer):
    """
    Serializer for audit log summary data.

    Provides a high-level overview of audit events for dashboard display.
    Data is computed server-side via get_audit_summary().

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture (audit trail)
    """

    period_days = serializers.IntegerField(
        help_text="Number of days in the summary period.",
    )
    total_events = serializers.IntegerField(
        help_text="Total number of audit events in the period.",
    )
    events_by_action = serializers.DictField(
        child=serializers.IntegerField(),
        help_text="Count of events grouped by action type.",
    )