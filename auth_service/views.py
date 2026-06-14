"""
Views for the Authentication Service.

Provides both template-based and REST API views for:
- User registration
- User login/logout
- User profile management
- Password change

Security controls:
- Generic error messages (no username enumeration) (OWASP A07)
- CSRF protection via Django middleware (OWASP A08)
- Session invalidation on logout (OWASP A07)
- Audit logging for all auth events (OWASP A09)
- @never_cache on auth pages (OWASP A05)
- @require_http_methods(["POST"]) on logout (CSRF logout prevention)
- IP tracking for login events (OWASP A09)

Maps to:
- OWASP A01:2021 - Broken Access Control
- OWASP A07:2021 - Identification and Authentication Failures
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V2.1 - Password Security
- ASVS V3.4 - Cookie-based Session Management
"""

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from auth_service.models import UserProfile
from auth_service.serializers import (
    PasswordChangeSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
    UserSerializer,
    UserUpdateSerializer,
)

# Lazy import to avoid circular imports
# audit_service.utils.log_audit_event is imported inside functions

logger = logging.getLogger("django")
audit_logger = logging.getLogger("audit")


# =============================================================================
# Helper Functions
# =============================================================================


def _get_client_ip(request):
    """
    Extract client IP from request, handling proxied requests.

    Checks X-Forwarded-For header first (for reverse proxy setups),
    falls back to REMOTE_ADDR.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture

    Args:
        request: Django request object

    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # Take the first IP (client) from the chain
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _log_audit_event(user, action, ip_address, details=""):
    """
    Log audit event with graceful failure handling.

    Uses lazy import to avoid circular imports with audit_service.

    Maps to:
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V1.2 - Architecture

    Args:
        user: User instance (can be None)
        action: Action string (from AuditLog.ActionChoices)
        ip_address: Client IP address
        details: Additional details string
    """
    try:
        from audit_service.utils import log_audit_event

        log_audit_event(
            user=user,
            action=action,
            service="auth_service",
            ip_address=ip_address,
            details=details,
        )
    except ImportError:
        # audit_service not yet available (e.g., during migration)
        logger.warning("audit_service not available, skipping audit log for action=%s", action)
    except Exception as e:
        # Audit failure must NOT crash the application
        logger.error("Failed to log audit event: %s", str(e))


# =============================================================================
# Template Views
# =============================================================================


@never_cache
def register_view(request):
    """
    User registration view (GET/POST).

    Security controls:
    - CSRF token in form (OWASP A08)
    - Generic error messages (no enumeration) (OWASP A07)
    - @never_cache prevents caching of registration form
    - Audit log on successful registration
    - Redirects to login on success (no auto-login)

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V2.1 - Password Security
    """
    if request.user.is_authenticated:
        return redirect("inventory_service:item_list")

    if request.method == "POST":
        serializer = UserRegistrationSerializer(data=request.POST)
        if serializer.is_valid():
            user = serializer.save()

            # Log registration event
            _log_audit_event(
                user=user,
                action="USER_REGISTERED",
                ip_address=_get_client_ip(request),
                details=f"New user registered: '{user.username}'",
            )

            logger.info("User registered: '%s'", user.username)
            messages.success(request, "Registration successful. Please log in.")
            return redirect("auth_service:login")
        else:
            # Generic error message (no field-specific enumeration)
            messages.error(request, "Registration failed. Please correct the errors below.")
    else:
        serializer = UserRegistrationSerializer()

    return render(request, "auth/register.html", {"serializer": serializer})


@never_cache
def login_view(request):
    """
    User login view (GET/POST).

    Security controls:
    - Generic "Invalid username or password" message (no enumeration)
    - @never_cache prevents caching of login form
    - IP tracking on successful login
    - Audit log on login success and failure
    - Session fixation protection via Django's login()

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V2.1 - Password Security
    - ASVS V3.4 - Cookie-based Session Management
    """
    if request.user.is_authenticated:
        return redirect("inventory_service:item_list")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                # Successful login
                login(request, user)

                # Track login IP
                user.last_login_ip = _get_client_ip(request)
                user.save(update_fields=["last_login_ip"])

                # Audit log for successful login
                _log_audit_event(
                    user=user,
                    action="USER_LOGIN",
                    ip_address=_get_client_ip(request),
                    details=f"User '{user.username}' logged in successfully",
                )

                logger.info("User logged in: '%s' from %s", user.username, _get_client_ip(request))
                messages.success(request, f"Welcome back, {user.first_name or user.username}!")
                return redirect("inventory_service:item_list")
            else:
                # Account disabled
                messages.error(request, "Invalid username or password.")
                _log_audit_event(
                    user=None,
                    action="LOGIN_FAILED",
                    ip_address=_get_client_ip(request),
                    details=f"Login attempt for disabled account: '{username}'",
                )
        else:
            # Invalid credentials — generic message to prevent enumeration
            messages.error(request, "Invalid username or password.")
            _log_audit_event(
                user=None,
                action="LOGIN_FAILED",
                ip_address=_get_client_ip(request),
                details=f"Failed login attempt for username: '{username}'",
            )

    return render(request, "auth/login.html")


@require_http_methods(["POST"])
def logout_view(request):
    """
    User logout view — POST-only to prevent CSRF logout attacks.

    Security controls:
    - POST-only (prevents GET-based logout via CSRF)
    - Session invalidation (logout)
    - Audit log

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - OWASP A08:2021 - Software and Data Integrity Failures (CSRF)
    - ASVS V3.4 - Cookie-based Session Management
    """
    if request.user.is_authenticated:
        username = request.user.username
        ip_address = _get_client_ip(request)

        # Audit log before logout
        _log_audit_event(
            user=request.user,
            action="USER_LOGOUT",
            ip_address=ip_address,
            details=f"User '{username}' logged out",
        )

        logger.info("User logged out: '%s'", username)

        # Invalidate session
        logout(request)
        messages.success(request, "You have been logged out.")

    return redirect("auth_service:login")


@login_required
@never_cache
def profile_view(request):
    """
    User profile view (GET/POST).

    Security controls:
    - @login_required enforces authentication
    - @never_cache prevents caching of profile data
    - Input validation via serializers (OWASP A03)
    - Role field excluded from update form (OWASP A01)
    - Audit log on profile update

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A03:2021 - Injection (input validation)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V4.2 - Operation Level Access Control
    """
    user = request.user

    # Ensure profile exists
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)

    if request.method == "POST":
        # Update user fields
        user_serializer = UserUpdateSerializer(user, data=request.POST, partial=True)
        # Update profile fields
        profile_serializer = UserProfileSerializer(profile, data=request.POST, partial=True)

        if user_serializer.is_valid() and profile_serializer.is_valid():
            user_serializer.save()
            profile_serializer.save()

            # Audit log
            _log_audit_event(
                user=user,
                action="PROFILE_UPDATED",
                ip_address=_get_client_ip(request),
                details=f"Profile updated for user '{user.username}'",
            )

            logger.info("Profile updated for user: '%s'", user.username)
            messages.success(request, "Profile updated successfully.")
            return redirect("auth_service:profile")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        user_serializer = UserUpdateSerializer(instance=user)
        profile_serializer = UserProfileSerializer(instance=profile)

    context = {
        "user_obj": user,
        "profile": profile,
        "user_serializer": user_serializer,
        "profile_serializer": profile_serializer,
    }
    return render(request, "auth/profile.html", context)


# =============================================================================
# REST API Views
# =============================================================================


class RegisterAPIView(APIView):
    """
    REST API endpoint for user registration.

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    permission_classes = [AllowAny]

    def post(self, request):
        """Register a new user."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            _log_audit_event(
                user=user,
                action="USER_REGISTERED",
                ip_address=_get_client_ip(request),
                details=f"API registration: '{user.username}'",
            )

            return Response(
                {
                    "message": "Registration successful.",
                    "user": UserSerializer(user).data,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {"errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class LoginAPIView(APIView):
    """
    REST API endpoint for user login.

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    permission_classes = [AllowAny]

    def post(self, request):
        """Authenticate and log in a user."""
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]

        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_active:
            login(request, user)

            user.last_login_ip = _get_client_ip(request)
            user.save(update_fields=["last_login_ip"])

            _log_audit_event(
                user=user,
                action="USER_LOGIN",
                ip_address=_get_client_ip(request),
                details=f"API login: '{user.username}'",
            )

            return Response(
                {
                    "message": "Login successful.",
                    "user": UserSerializer(user).data,
                },
                status=status.HTTP_200_OK,
            )

        # Generic error — no enumeration
        _log_audit_event(
            user=None,
            action="LOGIN_FAILED",
            ip_address=_get_client_ip(request),
            details=f"API failed login: '{username}'",
        )

        return Response(
            {"error": "Invalid username or password."},
            status=status.HTTP_401_UNAUTHORIZED,
        )


class LogoutAPIView(APIView):
    """
    REST API endpoint for user logout.

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V3.4 - Cookie-based Session Management
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Log out the current user and invalidate session."""
        username = request.user.username

        _log_audit_event(
            user=request.user,
            action="USER_LOGOUT",
            ip_address=_get_client_ip(request),
            details=f"API logout: '{username}'",
        )

        logout(request)
        return Response(
            {"message": "Logout successful."},
            status=status.HTTP_200_OK,
        )


class ProfileAPIView(APIView):
    """
    REST API endpoint for user profile management.

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    - ASVS V4.2 - Operation Level Access Control
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve current user's profile."""
        user = request.user
        return Response(
            UserSerializer(user).data,
            status=status.HTTP_200_OK,
        )

    def put(self, request):
        """Update current user's profile (excluding role)."""
        user = request.user
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()

            # Update profile fields
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile.objects.create(user=user)

            profile_serializer = UserProfileSerializer(
                profile, data=request.data, partial=True
            )
            if profile_serializer.is_valid():
                profile_serializer.save()

            _log_audit_event(
                user=user,
                action="PROFILE_UPDATED",
                ip_address=_get_client_ip(request),
                details=f"API profile update: '{user.username}'",
            )

            return Response(
                {
                    "message": "Profile updated.",
                    "user": UserSerializer(user).data,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class PasswordChangeAPIView(APIView):
    """
    REST API endpoint for password change.

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Change the current user's password."""
        serializer = PasswordChangeSerializer(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data["new_password"])
            user.save()

            # Keep user logged in with new password hash
            update_session_auth_hash(request, user)

            _log_audit_event(
                user=user,
                action="PASSWORD_CHANGED",
                ip_address=_get_client_ip(request),
                details=f"Password changed for user '{user.username}'",
            )

            logger.info("Password changed for user: '%s'", user.username)
            return Response(
                {"message": "Password changed successfully."},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )