"""
URL configuration for the Authentication Service (template views).

Maps URL patterns for:
- User registration
- User login
- User logout
- User profile

Maps to:
- OWASP A05:2021 - Security Misconfiguration (proper URL routing)
"""

from django.urls import path

from auth_service.views import (
    login_view,
    logout_view,
    profile_view,
    register_view,
)

app_name = "auth_service"

urlpatterns = [
    # Registration page
    path("register/", register_view, name="register"),
    # Login page
    path("login/", login_view, name="login"),
    # Logout (POST-only)
    path("logout/", logout_view, name="logout"),
    # User profile (view/edit)
    path("profile/", profile_view, name="profile"),
]