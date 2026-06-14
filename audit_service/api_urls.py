"""
URL configuration for the Audit Logging Service REST API.

All endpoints are admin-only (enforced via IsAdminOnly permission).

Maps to:
- OWASP A01:2021 - Broken Access Control
- ASVS V4.1 - Access Control Architecture
"""

from django.urls import path
from audit_service import views

app_name = "audit_api"

urlpatterns = [
    path(
        "logs/",
        views.AuditLogListAPIView.as_view(),
        name="audit-log-list",
    ),
    path(
        "logs/<uuid:pk>/",
        views.AuditLogDetailAPIView.as_view(),
        name="audit-log-detail",
    ),
    path(
        "summary/",
        views.AuditLogSummaryAPIView.as_view(),
        name="audit-log-summary",
    ),
]