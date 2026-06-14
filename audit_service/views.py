"""
Views for the Audit Logging Service.

Provides both template-based dashboard and REST API endpoints
for viewing audit logs and summaries. All endpoints are admin-only.

Security controls:
- Admin-only access enforced via @admin_only decorator and IsAdminOnly permission
- @never_cache prevents browser caching of sensitive audit data
- Queryset filtering uses ORM only (no raw SQL) (OWASP A03)
- Search and filter inputs validated against whitelists (OWASP A03)
- Results limited to prevent resource exhaustion (OWASP A05)
- All views log unauthorized access attempts (OWASP A09)

Maps to:
- OWASP A01:2021 - Broken Access Control (admin-only access)
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V4.1 - Access Control Architecture
- ASVS V1.2 - Architecture (audit trail)
"""

import logging

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from audit_service.models import AuditLog
from audit_service.permissions import IsAdminOnly, admin_only
from audit_service.serializers import AuditLogSerializer, AuditLogSummarySerializer
from audit_service.utils import get_audit_summary

logger = logging.getLogger("django")


# =============================================================================
# Whitelist constants for input validation (OWASP A03)
# =============================================================================

VALID_SERVICES = {"auth_service", "inventory_service", "audit_service"}
VALID_ACTIONS = {choice[0] for choice in AuditLog.Action.choices}
VALID_DAYS = {1, 7, 30, 90}


def _get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


# =============================================================================
# Template View — Audit Dashboard (admin-only)
# =============================================================================


@login_required
@admin_only
@never_cache
def dashboard_view(request):
    """
    Admin-only audit log dashboard.

    Displays audit logs with filtering by service, action, days, and search.
    Also shows a summary of events by action type.

    Security controls:
    - @login_required: requires authentication
    - @admin_only: requires admin role
    - @never_cache: prevents browser caching of sensitive data
    - Whitelist-based input validation for filters (OWASP A03)
    - Results limited to 100 entries (OWASP A05)

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V4.1 - Access Control Architecture
    """
    # Base queryset
    queryset = AuditLog.objects.select_related("user").all()

    # --- Filter: service (whitelist validation) ---
    service_filter = request.GET.get("service", "").strip()
    if service_filter and service_filter in VALID_SERVICES:
        queryset = queryset.filter(service=service_filter)

    # --- Filter: action (whitelist validation) ---
    action_filter = request.GET.get("action", "").strip()
    if action_filter and action_filter in VALID_ACTIONS:
        queryset = queryset.filter(action=action_filter)

    # --- Filter: days ---
    days_filter = request.GET.get("days", "7").strip()
    try:
        days = int(days_filter)
    except (ValueError, TypeError):
        days = 7
    if days not in VALID_DAYS:
        days = 7

    from datetime import timedelta
    from django.utils import timezone
    cutoff = timezone.now() - timedelta(days=days)
    queryset = queryset.filter(timestamp__gte=cutoff)

    # --- Filter: search (ORM icontains via Q objects, not raw SQL) ---
    search_query = request.GET.get("search", "").strip()
    if search_query and len(search_query) <= 200:
        queryset = queryset.filter(
            Q(username__icontains=search_query)
            | Q(details__icontains=search_query)
            | Q(ip_address__icontains=search_query)
        )

    # --- Limit results ---
    logs = queryset[:100]

    # --- Summary ---
    summary = get_audit_summary(days=days)

    context = {
        "logs": logs,
        "summary": summary,
        "current_service": service_filter,
        "current_action": action_filter,
        "current_days": days,
        "current_search": search_query,
        "valid_services": sorted(VALID_SERVICES),
        "valid_actions": sorted(AuditLog.Action.values),
        "valid_days": sorted(VALID_DAYS),
    }

    return render(request, "audit/dashboard.html", context)


# =============================================================================
# REST API Views (admin-only)
# =============================================================================


class AuditLogListAPIView(generics.ListAPIView):
    """
    REST API: List audit logs with filtering.

    Admin-only endpoint that returns paginated audit log entries.
    Supports filtering by service, action, username, IP address, and days.

    Security controls:
    - IsAdminOnly permission (OWASP A01)
    - Whitelist-based filter validation (OWASP A03)
    - Results limited to 500 entries (OWASP A05)

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V4.1 - Access Control Architecture
    """
    permission_classes = [IsAuthenticated, IsAdminOnly]
    serializer_class = AuditLogSerializer
    pagination_class = None  # Custom pagination via queryset slicing

    def get_queryset(self):
        """
        Build filtered queryset based on query parameters.
        All filters use whitelist validation (OWASP A03).
        """
        queryset = AuditLog.objects.select_related("user").all()

        # Filter by service (whitelist)
        service = self.request.query_params.get("service", "").strip()
        if service and service in VALID_SERVICES:
            queryset = queryset.filter(service=service)

        # Filter by action (whitelist)
        action = self.request.query_params.get("action", "").strip()
        if action and action in VALID_ACTIONS:
            queryset = queryset.filter(action=action)

        # Filter by username (ORM icontains)
        username = self.request.query_params.get("username", "").strip()
        if username and len(username) <= 150:
            queryset = queryset.filter(username__icontains=username)

        # Filter by IP address
        ip_address = self.request.query_params.get("ip_address", "").strip()
        if ip_address and len(ip_address) <= 45:
            queryset = queryset.filter(ip_address__icontains=ip_address)

        # Filter by days
        days_str = self.request.query_params.get("days", "").strip()
        if days_str:
            try:
                days = int(days_str)
                if days in VALID_DAYS:
                    from datetime import timedelta
                    from django.utils import timezone
                    cutoff = timezone.now() - timedelta(days=days)
                    queryset = queryset.filter(timestamp__gte=cutoff)
            except (ValueError, TypeError):
                pass

        # Limit results to prevent resource exhaustion
        return queryset[:500]


class AuditLogSummaryAPIView(APIView):
    """
    REST API: Get audit log summary.

    Returns event counts by action type for a specified period.
    Admin-only endpoint.

    Security controls:
    - IsAdminOnly permission (OWASP A01)
    - Days parameter validated against whitelist (OWASP A03)

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """
    permission_classes = [IsAuthenticated, IsAdminOnly]

    def get(self, request):
        """Return audit summary for the specified period."""
        days_str = request.query_params.get("days", "7").strip()
        try:
            days = int(days_str)
        except (ValueError, TypeError):
            days = 7

        if days not in VALID_DAYS:
            days = 7

        summary = get_audit_summary(days=days)
        serializer = AuditLogSummarySerializer(summary)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AuditLogDetailAPIView(generics.RetrieveAPIView):
    """
    REST API: Retrieve a single audit log entry.

    Admin-only endpoint for viewing individual log details.

    Security controls:
    - IsAdminOnly permission (OWASP A01)
    - UUID PK prevents ID enumeration (OWASP A01)

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """
    permission_classes = [IsAuthenticated, IsAdminOnly]
    serializer_class = AuditLogSerializer
    queryset = AuditLog.objects.all()