"""
Whitelist input validators for the Inventory Service.

All validators use a whitelist (allowlist) approach:
- Only explicitly allowed patterns pass validation
- Reject everything else by default

Security controls:
- Regex whitelist patterns (OWASP A03)
- HTML tag rejection for text fields (XSS prevention) (OWASP A03)
- Length limits (DoS prevention)
- File type/size/MIME validation (OWASP A04)
- UUID-based safe filenames to prevent path traversal (OWASP A04)

Maps to:
- OWASP A03:2021 - Injection
- OWASP A04:2021 - Insecure Design (file upload)
- OWASP ASVS V5.1 - Input Validation
- OWASP ASVS V5.2 - Sanitization and Sandboxing
- OWASP ASVS V12.1 - File Upload Requirements
"""

import os
import re
import uuid
import logging
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.core.exceptions import ValidationError

logger = logging.getLogger("django")

# =============================================================================
# Magic library — optional; gracefully degrade if libmagic not installed
# =============================================================================
try:
    import magic
    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False
    logger.warning(
        "python-magic / libmagic not available. "
        "MIME-type content validation will be skipped; "
        "extension whitelist and size checks still enforced."
    )

# =============================================================================
# Regex Patterns (Whitelist)
# =============================================================================

# Item name: alphanumeric + common punctuation, 1-100 chars
# Maps to OWASP A03:2021 - Injection
ITEM_NAME_REGEX = re.compile(r"^[a-zA-Z0-9\s\-\.,()&']{1,100}$")

# SKU: uppercase alphanumeric + hyphens only
# Maps to OWASP A03:2021 - Injection
SKU_REGEX = re.compile(r"^[A-Z0-9\-]{1,50}$")

# Category name: alphanumeric + spaces, hyphens, ampersand
# Maps to OWASP A03:2021 - Injection
CATEGORY_NAME_REGEX = re.compile(r"^[a-zA-Z0-9\s\-&]{1,50}$")

# HTML tag detection — reject any HTML to prevent stored XSS
# Maps to OWASP A03:2021 - Injection (XSS)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")

# Safe search query characters
SEARCH_QUERY_REGEX = re.compile(r"^[a-zA-Z0-9\s\.\-_,@#'\"()]{1,200}$")

# =============================================================================
# Numeric Limits
# =============================================================================
MAX_QUANTITY = 999_999
MAX_PRICE = Decimal("9999999.99")
MIN_PRICE = Decimal("0.00")


# =============================================================================
# Text Field Validators
# =============================================================================

def validate_item_name(value):
    """
    Validate inventory item name using whitelist pattern.

    Rules:
    - Alphanumeric with spaces, hyphens, dots, commas, parentheses, &, apostrophe
    - Length: 1-100 characters
    - No HTML tags

    Maps to:
    - OWASP A03:2021 - Injection
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Item name to validate

    Raises:
        ValidationError: If name doesn't match whitelist
    """
    if not value:
        raise ValidationError("Item name is required.")

    value = value.strip()

    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Item name must not contain HTML tags.")

    if not ITEM_NAME_REGEX.match(value):
        raise ValidationError(
            "Item name may only contain letters, numbers, spaces, hyphens, "
            "dots, commas, parentheses, ampersands, and apostrophes (1-100 characters)."
        )

    return value


def validate_item_description(value):
    """
    Validate item description field.

    Rules:
    - Maximum 1000 characters
    - No HTML tags (stored XSS prevention)

    Maps to:
    - OWASP A03:2021 - Injection (XSS prevention)
    - ASVS V5.2 - Sanitization and Sandboxing

    Args:
        value (str): Description text to validate

    Raises:
        ValidationError: If description contains HTML or exceeds length
    """
    if not value:
        return value

    if len(value) > 1000:
        raise ValidationError("Description must not exceed 1000 characters.")

    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Description must not contain HTML tags.")

    return value


def validate_sku(value):
    """
    Validate Stock Keeping Unit (SKU) code.

    Rules:
    - Uppercase letters, digits, and hyphens only
    - Length: 1-50 characters
    - Empty/None is allowed (optional field)

    Maps to:
    - OWASP A03:2021 - Injection
    - ASVS V5.1 - Input Validation

    Args:
        value (str): SKU code to validate

    Raises:
        ValidationError: If SKU doesn't match whitelist
    """
    if not value:
        return value

    value = value.strip().upper()

    if not SKU_REGEX.match(value):
        raise ValidationError(
            "SKU may only contain uppercase letters, digits, and hyphens (1-50 characters)."
        )

    return value


def validate_quantity(value):
    """
    Validate item quantity.

    Rules:
    - Non-negative integer
    - Maximum: 999,999

    Maps to:
    - OWASP A03:2021 - Injection (bounds checking)
    - ASVS V5.1 - Input Validation

    Args:
        value (int): Quantity to validate

    Raises:
        ValidationError: If quantity is out of range
    """
    try:
        qty = int(value)
    except (TypeError, ValueError):
        raise ValidationError("Quantity must be a whole number.")

    if qty < 0:
        raise ValidationError("Quantity must be 0 or greater.")

    if qty > MAX_QUANTITY:
        raise ValidationError(f"Quantity must not exceed {MAX_QUANTITY:,}.")

    return qty


def validate_price(value):
    """
    Validate item price as a Decimal.

    Rules:
    - Non-negative
    - Maximum: 9,999,999.99
    - At most 2 decimal places

    Maps to:
    - OWASP A03:2021 - Injection (bounds checking)
    - ASVS V5.1 - Input Validation

    Args:
        value: Price value (str, int, float, or Decimal)

    Raises:
        ValidationError: If price is invalid or out of range
    """
    try:
        price = Decimal(str(value))
    except (InvalidOperation, TypeError):
        raise ValidationError("Price must be a valid decimal number.")

    if price < MIN_PRICE:
        raise ValidationError("Price must be 0.00 or greater.")

    if price > MAX_PRICE:
        raise ValidationError(f"Price must not exceed {MAX_PRICE}.")

    return price


def validate_category_name(value):
    """
    Validate category name using whitelist pattern.

    Rules:
    - Alphanumeric with spaces, hyphens, and ampersands
    - Length: 1-50 characters

    Maps to:
    - OWASP A03:2021 - Injection
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Category name to validate

    Raises:
        ValidationError: If name doesn't match whitelist
    """
    if not value:
        raise ValidationError("Category name is required.")

    value = value.strip()

    if not CATEGORY_NAME_REGEX.match(value):
        raise ValidationError(
            "Category name may only contain letters, numbers, "
            "spaces, hyphens, and ampersands (1-50 characters)."
        )

    return value


def validate_search_query(value):
    """
    Validate search query to prevent injection attacks.

    Rules:
    - Maximum 200 characters
    - Safe characters only (alphanumeric + common punctuation)
    - No HTML tags

    Maps to:
    - OWASP A03:2021 - Injection (SQL injection, XSS prevention)
    - ASVS V5.1 - Input Validation

    Args:
        value (str): Search query to validate

    Raises:
        ValidationError: If query contains unsafe content
    """
    if not value:
        return value

    value = value.strip()

    if len(value) > 200:
        raise ValidationError("Search query must not exceed 200 characters.")

    if HTML_TAG_REGEX.search(value):
        raise ValidationError("Search query must not contain HTML tags.")

    if not SEARCH_QUERY_REGEX.match(value):
        raise ValidationError("Search query contains invalid characters.")

    return value


# =============================================================================
# File Upload Validators
# =============================================================================

def validate_file_upload(file):
    """
    Validate uploaded file for security compliance.

    Defense-in-depth approach (3 layers):
    1. File size limit (configured in settings.MAX_UPLOAD_SIZE)
    2. Extension whitelist check (settings.ALLOWED_UPLOAD_EXTENSIONS)
    3. MIME type check via libmagic content inspection (if available)

    Layer 3 reads the first 2048 bytes of the file content, making it
    resistant to extension spoofing (e.g., a PHP file renamed to .jpg).

    Maps to:
    - OWASP A04:2021 - Insecure Design
    - OWASP A03:2021 - Injection (malicious file execution)
    - ASVS V12.1 - File Upload Requirements

    Args:
        file: Django UploadedFile instance

    Raises:
        ValidationError: If file fails any security check
    """
    if not file:
        return

    # --- Layer 1: File size ---
    max_size = getattr(settings, "MAX_UPLOAD_SIZE", 5 * 1024 * 1024)
    if file.size > max_size:
        max_mb = max_size // (1024 * 1024)
        raise ValidationError(
            f"File size must not exceed {max_mb} MB. "
            f"Uploaded file is {file.size // 1024} KB."
        )

    # --- Layer 2: Extension whitelist ---
    allowed_extensions = getattr(
        settings,
        "ALLOWED_UPLOAD_EXTENSIONS",
        [".jpg", ".jpeg", ".png", ".gif"],
    )
    _, ext = os.path.splitext(file.name.lower())
    if ext not in allowed_extensions:
        raise ValidationError(
            f"File type '{ext}' is not allowed. "
            f"Allowed types: {', '.join(allowed_extensions)}."
        )

    # --- Layer 3: MIME type (content-based, not filename-based) ---
    if MAGIC_AVAILABLE:
        allowed_mimes = getattr(
            settings,
            "ALLOWED_UPLOAD_MIME_TYPES",
            ["image/jpeg", "image/png", "image/gif"],
        )
        try:
            # Read first 2048 bytes for MIME detection without loading entire file
            header = file.read(2048)
            file.seek(0)  # Reset pointer for downstream processing
            detected_mime = magic.from_buffer(header, mime=True)

            if detected_mime not in allowed_mimes:
                logger.warning(
                    "Blocked file upload with disallowed MIME type '%s' "
                    "(filename: '%s')",
                    detected_mime,
                    file.name,
                )
                raise ValidationError(
                    f"File content type '{detected_mime}' is not allowed. "
                    f"Allowed types: {', '.join(allowed_mimes)}."
                )
        except ValidationError:
            raise
        except Exception as exc:
            # libmagic error should not block legitimate uploads;
            # log and fall back to extension-only validation.
            logger.error("MIME detection error for '%s': %s", file.name, exc)
    else:
        logger.warning(
            "MIME type validation skipped for '%s' (libmagic unavailable). "
            "Extension '%s' was checked.",
            file.name,
            ext,
        )


def generate_safe_filename(original_filename):
    """
    Generate a UUID-based filename to prevent path traversal and filename collisions.

    Preserves the file extension for correct content-type serving.
    The UUID name prevents:
    - Path traversal attacks (../../etc/passwd)
    - Directory enumeration
    - Filename-based information disclosure

    Maps to:
    - OWASP A04:2021 - Insecure Design
    - ASVS V12.1 - File Upload Requirements

    Args:
        original_filename (str): Original uploaded filename

    Returns:
        str: UUID-based safe filename with preserved extension
    """
    _, ext = os.path.splitext(original_filename.lower())
    # Only preserve whitelisted extensions; default to .bin for unknown types
    allowed_extensions = getattr(
        settings,
        "ALLOWED_UPLOAD_EXTENSIONS",
        [".jpg", ".jpeg", ".png", ".gif"],
    )
    safe_ext = ext if ext in allowed_extensions else ".bin"
    return f"{uuid.uuid4().hex}{safe_ext}"