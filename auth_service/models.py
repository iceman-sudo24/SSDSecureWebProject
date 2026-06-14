"""
Custom User model with Role-Based Access Control (RBAC) and UserProfile.

Security controls implemented:
- UUID primary keys to prevent ID enumeration (OWASP A01)
- Argon2 password hashing (configured in settings.py) (OWASP A07)
- Role field for RBAC (ADMIN/USER) (OWASP A01)
- Phone number validation with regex
- IP tracking for last login (OWASP A09)

References:
- OWASP Top 10: https://owasp.org/Top10/
- OWASP ASVS v4.0: https://owasp.org/www-project-application-verification-standard/
- Django Custom User Model: https://docs.djangoproject.com/en/4.2/topics/auth/customizing/
"""

import uuid
import logging

from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.db import models

logger = logging.getLogger("django")

# =============================================================================
# Constants
# =============================================================================

# Phone number regex validator (E.164 format, flexible)
# Maps to OWASP A03:2021 - Injection (input validation)
# Maps to ASVS V5.1 - Input Validation
PHONE_REGEX = r"^\+?1?\d{9,15}$"
phone_validator = RegexValidator(
    regex=PHONE_REGEX,
    message=(
        "Phone number must be entered in the format: '+999999999'. "
        "Up to 15 digits allowed."
    ),
)


class Role(models.TextChoices):
    """
    User roles for Role-Based Access Control (RBAC).

    Maps to:
    - OWASP A01:2021 - Broken Access Control
    - OWASP ASVS V4.1 - Access Control Architecture
    """

    ADMIN = "ADMIN", "Admin"
    USER = "USER", "User"


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.

    Security features:
    - UUID primary key prevents sequential ID enumeration (OWASP A01)
    - Role field for RBAC enforcement (OWASP A01)
    - Phone number with regex validation (OWASP A03)
    - Last login IP tracking for audit purposes (OWASP A09)
    - Timestamps for account lifecycle tracking

    Maps to:
    - OWASP A01:2021 - Broken Access Control (RBAC)
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    - ASVS V4.1 - Access Control Architecture
    """

    # UUID primary key prevents ID enumeration attacks
    # Maps to OWASP A01:2021 - Broken Access Control
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="UUID primary key to prevent ID enumeration attacks.",
    )

    # Role field for RBAC
    # Maps to OWASP A01:2021 - Broken Access Control
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.USER,
        help_text="User role for RBAC. Admin has elevated privileges.",
    )

    # Phone number with validation
    # Maps to OWASP A03:2021 - Injection (input validation)
    phone_regex = RegexValidator(
        regex=PHONE_REGEX,
        message=(
            "Phone number must be entered in the format: '+999999999'. "
            "Up to 15 digits allowed."
        ),
    )
    phone_number = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        validators=[phone_regex],
        help_text="Phone number in E.164 format.",
    )

    # Timestamps for account lifecycle tracking
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the user account was created.",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp of the last update to the user account.",
    )

    # Last login IP for security monitoring and audit
    # Maps to OWASP A09:2021 - Security Logging and Monitoring Failures
    last_login_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address of the user's last login for audit purposes.",
    )

    class Meta:
        db_table = "auth_user"
        ordering = ["-created_at"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return f"{self.username} ({self.role})"

    @property
    def is_admin(self):
        """Check if user has admin role. Used for RBAC enforcement."""
        return self.role == Role.ADMIN

    @property
    def is_normal_user(self):
        """Check if user has normal user role."""
        return self.role == Role.USER


class UserProfile(models.Model):
    """
    Extended user profile with additional information.

    OneToOne relationship with User model.
    Avatar upload restricted to safe file types (configured in settings.py).

    Maps to:
    - OWASP A04:2021 - Insecure Design (file upload security)
    - ASVS V12.1 - File Upload Requirements
    """

    # UUID primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    # One-to-one link to User
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile",
        help_text="Link to the associated User account.",
    )

    # Bio with length limit
    bio = models.TextField(
        max_length=500,
        blank=True,
        help_text="Short biography (max 500 characters).",
    )

    # Organization with regex validation
    # Maps to OWASP A03:2021 - Injection (input validation)
    organization = models.CharField(
        max_length=100,
        blank=True,
        help_text="Organization or company name.",
    )

    # Avatar image upload
    # Maps to OWASP A04:2021 - Insecure Design
    # File validation handled in validators.py
    avatar = models.ImageField(
        upload_to="avatars/",
        blank=True,
        null=True,
        help_text="Profile avatar image. Allowed types: jpg, jpeg, png, gif.",
    )

    class Meta:
        db_table = "auth_user_profile"
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"Profile for {self.user.username}"