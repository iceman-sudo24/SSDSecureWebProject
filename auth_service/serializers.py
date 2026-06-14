"""
Serializers for the Authentication Service.

Provides serialization/deserialization for:
- User registration with password validation
- User login
- User profile management
- Password change

Security controls:
- Password is write-only (never exposed in responses) (OWASP A07)
- Minimum password length of 12 characters (OWASP A07)
- Username validated with whitelist pattern (OWASP A03)
- Email uniqueness check (case-insensitive) (OWASP A07)
- Role field excluded from update serializer (prevents privilege escalation) (OWASP A01)
- Argon2 password hashing via set_password (OWASP A07)

Maps to:
- OWASP A01:2021 - Broken Access Control (privilege escalation prevention)
- OWASP A03:2021 - Injection (input validation)
- OWASP A07:2021 - Identification and Authentication Failures
- ASVS V2.1 - Password Security
- ASVS V5.1 - Input Validation
"""

import logging

from django.contrib.auth import password_validation
from django.contrib.auth.hashers import check_password
from rest_framework import serializers

from auth_service.models import User, UserProfile
from auth_service.validators import validate_username, validate_bio

logger = logging.getLogger("django")


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Security features:
    - Password write-only (never in responses)
    - Minimum 12 characters (OWASP A07)
    - Django password validators applied
    - Username whitelist validation (OWASP A03)
    - Email uniqueness (case-insensitive)
    - Password confirmation required

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    password = serializers.CharField(
        write_only=True,
        min_length=12,
        style={"input_type": "password"},
        validators=[password_validation.validate_password],
        help_text="Password must be at least 12 characters.",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Confirm your password.",
    )

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password",
            "password_confirm",
            "first_name",
            "last_name",
            "phone_number",
        )

    def validate_username(self, value):
        """Validate username using whitelist pattern."""
        return validate_username(value)

    def validate_email(self, value):
        """
        Validate email uniqueness (case-insensitive).
        Maps to OWASP A07:2021 - Identification and Authentication Failures
        """
        if not value:
            raise serializers.ValidationError("Email is required.")

        value = value.strip().lower()

        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "A user with this email already exists."
            )

        return value

    def validate(self, attrs):
        """Ensure passwords match."""
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        """
        Create user with Argon2-hashed password.

        Maps to OWASP A07:2021 - Identification and Authentication Failures
        """
        validated_data.pop("password_confirm")

        # Create user with Argon2 hashing via set_password
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            phone_number=validated_data.get("phone_number"),
        )

        # Create associated UserProfile
        UserProfile.objects.create(user=user)

        logger.info("User registered: '%s'", user.username)
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login.

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    username = serializers.CharField(
        help_text="Username for authentication.",
    )
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="User password.",
    )


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for UserProfile model.

    Maps to:
    - OWASP A03:2021 - Injection (input validation via validators)
    - ASVS V5.1 - Input Validation
    """

    class Meta:
        model = UserProfile
        fields = ("bio", "organization", "avatar")

    def validate_bio(self, value):
        """Validate bio field using whitelist validator."""
        return validate_bio(value)


class UserSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for User data.

    SECURITY: Never exposes password or sensitive internal fields.
    Maps to OWASP A07:2021 - Identification and Authentication Failures
    """

    is_admin = serializers.BooleanField(read_only=True)
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
            "is_admin",
            "phone_number",
            "created_at",
            "profile",
        )
        read_only_fields = fields


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile information.

    SECURITY: Role field is intentionally EXCLUDED to prevent
    privilege escalation attacks.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (privilege escalation)
    - ASVS V4.2 - Operation Level Access Control
    """

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
            "phone_number",
        )
        # NOTE: 'role' is deliberately excluded to prevent privilege escalation


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change.

    Security features:
    - Current password verification required
    - New password validated against Django password validators
    - Password confirmation required

    Maps to:
    - OWASP A07:2021 - Identification and Authentication Failures
    - ASVS V2.1 - Password Security
    """

    old_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Current password for verification.",
    )
    new_password = serializers.CharField(
        write_only=True,
        min_length=12,
        style={"input_type": "password"},
        validators=[password_validation.validate_password],
        help_text="New password (min 12 characters).",
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Confirm new password.",
    )

    def validate_old_password(self, value):
        """Verify the current password is correct."""
        user = self.context["request"].user
        if not check_password(value, user.password):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs):
        """Ensure new passwords match."""
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "New passwords do not match."}
            )
        return attrs