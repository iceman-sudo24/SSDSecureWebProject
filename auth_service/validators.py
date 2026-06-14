"""
Whitelist input validators for the Authentication Service.

All validators use whitelist (allowlist) approach:
- Only explicitly allowed patterns pass validation
- Reject everything else by default

Security controls:
- Regex whitelist patterns (OWASP A03)
- HTML tag rejection for text fields (OWASP A03: XSS prevention)
- Length limits to prevent buffer overflow / DoS
- Reserved name blacklist to prevent impersonation

Maps to:
- OWASP A03:2021 - Injection
- OWASP ASVS V5.1 - Input Validation
- OWASP ASVS V5.2 - Sanitization and Sandboxing
"""

import re
import logging

from django.core.exceptions import ValidationError

logger = logging.getLogger("django")

# =============================================================================
# Regex Patterns (Whitelist Approach)
# =============================================================================

# Username: starts with letter, allows alphanumeric, hyphens, underscores
# Maps to OWASP A03:2021 - Injection
USERNAME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,29}$")

# Display name: alphanumeric with spaces, dots, hyphens, apostrophes
# Maps to OWASP A03:2021 - Injection
DISPLAY_NAME_REGEX = re.compile(r"^[a-zA-Z0-9\s\.\-']{1,100}$")

# Organization: alphanumeric with common business characters
# Maps to OWASP A03:2021 - Injection
ORGANIZATION_REGEX = re.compile(r"^[a-zA-Z0-9\s\-\.,&']{1,100}$")

# HTML tag pattern for rejection
# Maps to OWASP A03:2021 - Injection (XSS prevention)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")

# =============================================================================
# Reserved Names (Blacklist)
# =============================================================================
# Prevents impersonation of system accounts and URL conflicts
# Maps to OWASP A01:2021 - Broken Access Control
RESERVED_NAMES = frozenset({
    "admin",
    "administrator",
    "root",
    "superuser",
    "system",
    "moderator",
    "support",
    "help",
    "info",
    "webmaster",
    "security",
    "null",
    "undefined",
    "none",
    "true",
    "false",
    "api",
    "auth",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "dashboard",
    "settings",
    "config",
    "test",
    "debug",
    "static",
    "media",
    "inventory",
    "audit",
})


def validate_username(value):
    """
    Validate username using whitelist pattern.

    Rules:
    - Must start with a letter
    - Can contain letters, numbers, hyphens, underscores
    - Length: 3-30 characters
    - Must not be a reserved name

    Maps to:
    - OWASP A03:2021 - Injection (input validation)
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Username to validate

    Raises:
        ValidationError: If username doesn't match whitelist or is reserved
    """
    if not value:
        raise ValidationError("Username is required.")

    value = value.strip()

    # Check against whitelist pattern
    if not USERNAME_REGEX.match(value):
        raise ValidationError(
            "Username must start with a letter and contain only "
            "letters, numbers, hyphens, and underscores (3-30 characters)."
        )

    # Check against reserved names (case-insensitive)
    if value.lower() in RESERVED_NAMES:
        logger.warning("Attempted use of reserved username: '%s'", value)
        raise ValidationError(
            "This username is not available. Please choose a different one."
        )

    return value


def validate_display_name(value):
    """
    Validate display name using whitelist pattern.

    Rules:
    - Alphanumeric with spaces, dots, hyphens, apostrophes
    - Length: 1-100 characters
    - No HTML tags allowed

    Maps to:
    - OWASP A03:2021 - Injection
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Display name to validate

    Raises:
        ValidationError: If display name doesn't match whitelist
    """
    if not value:
        return value

    value = value.strip()

    if len(value) > 100:
        raise ValidationError("Display name must not exceed 100 characters.")

    # Reject HTML tags
    # Maps to OWASP A03:2021 - Injection (XSS prevention)
    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Display name must not contain HTML tags.")

    if not DISPLAY_NAME_REGEX.match(value):
        raise ValidationError(
            "Display name can only contain letters, numbers, "
            "spaces, dots, hyphens, and apostrophes."
        )

    return value


def validate_bio(value):
    """
    Validate bio field.

    Rules:
    - Maximum 500 characters
    - No HTML tags allowed (XSS prevention)

    Maps to:
    - OWASP A03:2021 - Injection (XSS prevention via sanitization)
    - ASVS V5.2 - Sanitization and Sandboxing

    Args:
        value (str): Bio text to validate

    Raises:
        ValidationError: If bio contains HTML tags or exceeds length
    """
    if not value:
        return value

    # Enforce max length
    if len(value) > 500:
        raise ValidationError("Bio must not exceed 500 characters.")

    # Reject HTML tags to prevent stored XSS
    # Maps to OWASP A03:2021 - Injection
    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Bio must not contain HTML tags.")

    return value


def validate_organization(value):
    """
    Validate organization name using whitelist pattern.

    Rules:
    - Alphanumeric with common business characters (hyphens, dots, commas, ampersands, apostrophes)
    - Length: 1-100 characters
    - No HTML tags

    Maps to:
    - OWASP A03:2021 - Injection
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Organization name to validate

    Raises:
        ValidationError: If organization name doesn't match whitelist
    """
    if not value:
        return value

    value = value.strip()

    if len(value) > 100:
        raise ValidationError("Organization name must not exceed 100 characters.")

    # Reject HTML tags
    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Organization name must not contain HTML tags.")

    if not ORGANIZATION_REGEX.match(value):
        raise ValidationError(
            "Organization name can only contain letters, numbers, "
            "spaces, hyphens, dots, commas, ampersands, and apostrophes."
        )

    return value


def validate_search_query(value):
    """
    Validate search query input.

    Rules:
    - Maximum 200 characters
    - Safe characters only (alphanumeric, spaces, common punctuation)
    - No HTML tags
    - No SQL injection patterns

    Maps to:
    - OWASP A03:2021 - Injection (SQL injection, XSS prevention)
    - ASVS V5.1 - Input Validation
    - ASVS V5.3 - Output Encoding

    Args:
        value (str): Search query to validate

    Raises:
        ValidationError: If search query is unsafe
    """
    if not value:
        return value

    value = value.strip()

    if len(value) > 200:
        raise ValidationError("Search query must not exceed 200 characters.")

    # Reject HTML tags
    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Search query must not contain HTML tags.")

    # Allow only safe characters: alphanumeric, spaces, and basic punctuation
    safe_pattern = re.compile(r"^[a-zA-Z0-9\s\.\-_,@#'\"()]+$")
    if not safe_pattern.match(value):
        raise ValidationError(
            "Search query contains invalid characters."
        )

    return value