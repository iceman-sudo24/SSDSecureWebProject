"""
URL configuration for the Audit Logging Service (template views).

Maps to:
- OWASP A01:2021 - Broken Access Control
- ASVS V4.1 - Access Control Architecture
"""

from django.urls import path
from audit_service import views

app_name = "audit_service"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
]