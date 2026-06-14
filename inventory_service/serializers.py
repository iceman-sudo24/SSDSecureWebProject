"""
Serializers for the Inventory Service.

Security controls:
- owner is ALWAYS set from request.user on the server — never from user input (OWASP A01)
- role field excluded from all update serializers (OWASP A01)
- Image field validated via validate_file_upload() (OWASP A04)
- Input validation delegates to model validators and custom validators.py (OWASP A03)

Maps to:
- OWASP A01:2021 - Broken Access Control (server-side ownership)
- OWASP A03:2021 - Injection (input validation)
- OWASP A04:2021 - Insecure Design (file upload)
- ASVS V4.2 - Operation Level Access Control
- ASVS V5.1 - Input Validation
"""

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as DRFValidationError

from inventory_service.models import Category, InventoryAuditLog, InventoryItem
from inventory_service.validators import (
    generate_safe_filename,
    validate_file_upload,
    validate_item_description,
    validate_item_name,
    validate_sku,
)


# =============================================================================
# Category
# =============================================================================

class CategorySerializer(serializers.ModelSerializer):
    """Read/write serializer for Category."""

    class Meta:
        model = Category
        fields = ["id", "name", "description", "created_at"]
        read_only_fields = ["id", "created_at"]


# =============================================================================
# InventoryItem — full detail
# =============================================================================

class InventoryItemSerializer(serializers.ModelSerializer):
    """
    Full-detail serializer for a single InventoryItem.

    owner and category are read-only — they cannot be changed via the API.
    Convenience source fields expose human-readable names.
    """

    owner_username = serializers.CharField(source="owner.username", read_only=True)
    category_name = serializers.CharField(
        source="category.name", read_only=True, allow_null=True
    )

    class Meta:
        model = InventoryItem
        fields = [
            "id",
            "owner",
            "owner_username",
            "name",
            "description",
            "category",
            "category_name",
            "quantity",
            "price",
            "sku",
            "status",
            "image",
            "created_at",
            "updated_at",
        ]
        # owner is always set from request.user — never writable via API
        # Maps to OWASP A01:2021 - Broken Access Control
        read_only_fields = [
            "id", "owner", "owner_username", "category_name",
            "created_at", "updated_at",
        ]


# =============================================================================
# InventoryItem — lightweight list view
# =============================================================================

class InventoryItemListSerializer(serializers.ModelSerializer):
    """
    Lightweight read-only serializer for list endpoints.

    Avoids loading heavy fields (description, image) for performance.
    """

    owner_username = serializers.CharField(source="owner.username", read_only=True)
    category_name = serializers.CharField(
        source="category.name", read_only=True, allow_null=True
    )

    class Meta:
        model = InventoryItem
        fields = [
            "id",
            "name",
            "category_name",
            "quantity",
            "price",
            "sku",
            "status",
            "owner_username",
            "created_at",
        ]
        read_only_fields = fields


# =============================================================================
# InventoryItem — create
# =============================================================================

class InventoryItemCreateSerializer(serializers.ModelSerializer):
    """
    Create serializer for InventoryItem.

    SECURITY: owner field is intentionally excluded.
    create() sets owner = request.user from the serializer context.
    This prevents a user from claiming ownership of another user's item.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (server-side ownership assignment)
    - ASVS V4.2 - Operation Level Access Control
    """

    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = InventoryItem
        fields = ["name", "description", "category", "quantity", "price", "sku", "image"]

    def validate_name(self, value):
        try:
            return validate_item_name(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_description(self, value):
        try:
            return validate_item_description(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_sku(self, value):
        if not value:
            return None
        try:
            return validate_sku(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_image(self, file):
        if not file:
            return file
        try:
            validate_file_upload(file)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc
        # Rename to UUID-based filename to prevent path traversal
        file.name = generate_safe_filename(file.name)
        return file

    def create(self, validated_data):
        # Owner is ALWAYS taken from the authenticated request user
        # Never from user-submitted data
        # Maps to OWASP A01:2021 - Broken Access Control
        validated_data["owner"] = self.context["request"].user
        return super().create(validated_data)


# =============================================================================
# InventoryItem — update
# =============================================================================

class InventoryItemUpdateSerializer(serializers.ModelSerializer):
    """
    Update serializer for InventoryItem.

    SECURITY: owner field is excluded — prevents ownership transfer attacks.
    status can be changed on update (unlike create where it auto-derives from quantity).

    Maps to:
    - OWASP A01:2021 - Broken Access Control (no ownership transfer)
    - ASVS V4.2 - Operation Level Access Control
    """

    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = InventoryItem
        fields = [
            "name", "description", "category", "quantity",
            "price", "sku", "status", "image",
        ]

    def validate_name(self, value):
        try:
            return validate_item_name(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_description(self, value):
        try:
            return validate_item_description(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_sku(self, value):
        if not value:
            return None
        try:
            return validate_sku(value)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc

    def validate_image(self, file):
        if not file:
            return file
        try:
            validate_file_upload(file)
        except DjangoValidationError as exc:
            raise DRFValidationError(exc.message) from exc
        file.name = generate_safe_filename(file.name)
        return file


# =============================================================================
# InventoryAuditLog
# =============================================================================

class InventoryAuditLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for inventory-level audit log entries."""

    item_name = serializers.CharField(
        source="item.name", read_only=True, allow_null=True
    )
    username = serializers.CharField(
        source="user.username", read_only=True, allow_null=True
    )

    class Meta:
        model = InventoryAuditLog
        fields = [
            "id",
            "item",
            "item_name",
            "item_name_snapshot",
            "user",
            "username",
            "username_snapshot",
            "action",
            "field_changed",
            "old_value",
            "new_value",
            "ip_address",
            "timestamp",
        ]
        read_only_fields = fields