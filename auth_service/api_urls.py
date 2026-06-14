"""
REST API URL configuration for the Authentication Service.

Maps API endpoint patterns for:
- User registration (POST)
- User login (POST)
- User logout (POST)
- User profile (GET/PUT)
- Password change (POST)

Maps to:
- OWASP A05:2021 - Security Misconfiguration (proper URL routing)
"""

from django.urls import path

from auth_service.views import (
    LoginAPIView,
    LogoutAPIView,
    PasswordChangeAPIView,
    ProfileAPIView,
    RegisterAPIView,
)

app_name = "auth_api"

urlpatterns = [
    # Registration endpoint
    path("register/", RegisterAPIView.as_view(), name="register"),
    # Login endpoint
    path("login/", LoginAPIView.as_view(), name="login"),
    # Logout endpoint (POST-only)
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    # User profile endpoint (GET/PUT)
    path("profile/", ProfileAPIView.as_view(), name="profile"),
    # Password change endpoint
    path("password/change/", PasswordChangeAPIView.as_view(), name="password-change"),
]