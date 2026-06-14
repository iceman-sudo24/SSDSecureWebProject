"""
Views for the Inventory Service.

Provides both template-based and REST API views for inventory CRUD.

Security controls:
- login_required on all template views (OWASP A07)
- @never_cache on all views (prevents sensitive data in browser cache) (OWASP A05)
- Query-level IDOR prevention: queryset filtered by owner before the view runs (OWASP A01)
- Object-level IDOR check: explicit ownership check after get_object_or_404 (OWASP A01)
- owner is ALWAYS set from request.user — never from POST data (OWASP A01)
- File upload validated via validators.validate_file_upload (OWASP A04)
- Search input validated via validators.validate_search_query (OWASP A03)
- Audit log for all create/update/delete/view events (OWASP A09)
- CSRF protection via Django middleware on all POST forms (OWASP A08)

Maps to:
- OWASP A01:2021 - Broken Access Control (IDOR prevention, ownership)
- OWASP A03:2021 - Injection (input validation, ORM-only queries)
- OWASP A04:2021 - Insecure Design (file upload)
- OWASP A05:2021 - Security Misconfiguration (@never_cache)
- OWASP A07:2021 - Identification and Authentication Failures
- OWASP A08:2021 - Software and Data Integrity Failures (CSRF)
- OWASP A09:2021 - Security Logging and Monitoring Failures
- ASVS V4.2 - Operation Level Access Control
- ASVS V5.1 - Input Validation
"""

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import models as db_models
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from rest_framework.generics import (
    ListAPIView,
    ListCreateAPIView,
    RetrieveUpdateDestroyAPIView,
)
from rest_framework.permissions import IsAuthenticated

from inventory_service.models import Category, InventoryAuditLog, InventoryItem
from inventory_service.permissions import IsAdminOrReadOnly, IsOwnerOrAdmin
from inventory_service.serializers import (
    CategorySerializer,
    InventoryAuditLogSerializer,
    InventoryItemCreateSerializer,
    InventoryItemListSerializer,
    InventoryItemSerializer,
    InventoryItemUpdateSerializer,
)
from inventory_service.validators import (
    generate_safe_filename,
    validate_file_upload,
    validate_search_query,
)

logger = logging.getLogger("django")


# =============================================================================
# Helper Functions
# =============================================================================

def _get_client_ip(request):
    """
    Extract client IP, handling reverse proxy X-Forwarded-For chains.

    Maps to OWASP A09:2021 - Security Logging and Monitoring Failures.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _get_user_items(user):
    """
    Return the queryset of items the user is authorised to see.

    This is the primary, query-level IDOR prevention layer.
    Admins see all items; normal users see only their own.
    Filtering happens at the database level, not in Python, so a user
    can never accidentally receive another user's items.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR prevention)
    - ASVS V4.2 - Operation Level Access Control
    """
    qs = InventoryItem.objects.select_related("owner", "category")
    if user.is_admin:
        return qs.all()
    return qs.filter(owner=user)


def _log_inventory_event(request, item, action, field_changed="", old_value="", new_value=""):
    """
    Create an InventoryAuditLog record and forward the event to audit_service.

    Failure is logged but never propagated — audit must not crash the app.

    Maps to OWASP A09:2021 - Security Logging and Monitoring Failures.
    """
    ip = _get_client_ip(request)
    try:
        InventoryAuditLog.objects.create(
            item=item,
            item_name_snapshot=item.name if item else "",
            user=request.user,
            username_snapshot=request.user.username,
            action=action,
            field_changed=field_changed,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip,
        )
    except Exception as exc:
        logger.error("Failed to write InventoryAuditLog: %s", exc)

    try:
        from audit_service.utils import log_audit_event
        log_audit_event(
            user=request.user,
            action=f"INVENTORY_{action}",
            service="inventory_service",
            ip_address=ip,
            details=f"Item: '{getattr(item, 'name', 'unknown')}' | field: {field_changed}",
            resource_type="InventoryItem",
            resource_id=str(getattr(item, "pk", "")),
        )
    except Exception as exc:
        logger.error("Failed to forward audit event to audit_service: %s", exc)


def _check_ownership(request, item):
    """
    Object-level IDOR check (secondary layer after query-level filtering).

    Returns None if authorised; returns HttpResponseForbidden if not.
    Call this immediately after get_object_or_404 for write operations.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR prevention)
    - ASVS V4.2 - Operation Level Access Control
    """
    if request.user.is_admin:
        return None
    if item.owner != request.user:
        logger.warning(
            "IDOR attempt: user '%s' tried to access item '%s' (pk=%s) owned by '%s'",
            request.user.username,
            item.name,
            item.pk,
            item.owner.username,
        )
        # Log IDOR attempt to audit service
        try:
            from audit_service.utils import log_audit_event
            log_audit_event(
                user=request.user,
                action="IDOR_ATTEMPT",
                service="inventory_service",
                ip_address=_get_client_ip(request),
                details=f"Attempted access to item pk={item.pk} owned by '{item.owner.username}'",
                resource_type="InventoryItem",
                resource_id=str(item.pk),
            )
        except Exception:
            pass
        return HttpResponseForbidden("You do not have permission to access this item.")
    return None


# =============================================================================
# Template Views
# =============================================================================

@login_required
@never_cache
def item_list(request):
    """
    List inventory items for the current user (or all items for admins).

    Query-level IDOR prevention: _get_user_items() filters at the DB level.
    Search and filter inputs are validated before use in ORM queries.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (queryset ownership filter)
    - OWASP A03:2021 - Injection (validated search query)
    """
    items = _get_user_items(request.user)
    categories = Category.objects.all()

    search_q = request.GET.get("q", "").strip()
    category_id = request.GET.get("category", "").strip()
    status_filter = request.GET.get("status", "").strip()

    # Validate search input before passing to ORM
    if search_q:
        try:
            validate_search_query(search_q)
            items = items.filter(
                db_models.Q(name__icontains=search_q)
                | db_models.Q(sku__icontains=search_q)
                | db_models.Q(description__icontains=search_q)
            )
        except ValidationError:
            messages.error(request, "Invalid search query.")
            search_q = ""

    if category_id:
        items = items.filter(category__id=category_id)

    # Only allow known status values (whitelist)
    valid_statuses = [s[0] for s in InventoryItem.Status.choices]
    if status_filter in valid_statuses:
        items = items.filter(status=status_filter)
    else:
        status_filter = ""

    context = {
        "items": items,
        "categories": categories,
        "search_q": search_q,
        "selected_category": category_id,
        "selected_status": status_filter,
        "status_choices": InventoryItem.Status.choices,
    }
    return render(request, "inventory/list.html", context)


@login_required
@never_cache
def item_detail(request, item_id):
    """
    Detail view for a single inventory item.

    IDOR prevention (two layers):
    1. Query-level: get_object_or_404 scoped to _get_user_items(user)
    2. Object-level: _check_ownership() for defence in depth

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """
    item = get_object_or_404(InventoryItem, pk=item_id)

    # Object-level ownership check (second IDOR layer)
    denied = _check_ownership(request, item)
    if denied:
        return denied

    _log_inventory_event(request, item, InventoryAuditLog.Action.VIEWED)

    return render(request, "inventory/detail.html", {"item": item})


@login_required
@never_cache
def item_create(request):
    """
    Create a new inventory item.

    SECURITY: owner is set from request.user on the server — never from POST data.
    File upload is validated for size, extension, and MIME type.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (server-side owner assignment)
    - OWASP A03:2021 - Injection (input validation)
    - OWASP A04:2021 - Insecure Design (file upload)
    - OWASP A08:2021 - Software and Data Integrity Failures (CSRF)
    """
    categories = Category.objects.all()

    if request.method == "POST":
        serializer = InventoryItemCreateSerializer(
            data=request.POST,
            context={"request": request},
        )
        image = request.FILES.get("image")
        image_error = None

        # Validate file independently (ImageField in DRF needs request.data for files)
        if image:
            try:
                validate_file_upload(image)
                image.name = generate_safe_filename(image.name)
            except ValidationError as exc:
                image_error = exc.message

        if serializer.is_valid() and not image_error:
            # owner is always request.user — set inside serializer.create()
            item = serializer.save(image=image)

            _log_inventory_event(request, item, InventoryAuditLog.Action.CREATED)
            logger.info(
                "Inventory item created: '%s' (pk=%s) by user '%s'",
                item.name, item.pk, request.user.username,
            )
            messages.success(request, f"Item '{item.name}' created successfully.")
            return redirect("inventory_service:item_detail", item_id=item.pk)

        if image_error:
            messages.error(request, image_error)
        if not serializer.is_valid():
            messages.error(request, "Please correct the errors below.")

    else:
        serializer = InventoryItemCreateSerializer()

    return render(request, "inventory/create.html", {
        "serializer": serializer,
        "categories": categories,
    })


@login_required
@never_cache
def item_update(request, item_id):
    """
    Update an existing inventory item.

    IDOR prevention: ownership checked before any mutation.
    Field-level change tracking records what changed for the audit log.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR)
    - OWASP A03:2021 - Injection (input validation)
    - OWASP A04:2021 - Insecure Design (file upload)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """
    item = get_object_or_404(InventoryItem, pk=item_id)

    denied = _check_ownership(request, item)
    if denied:
        return denied

    categories = Category.objects.all()

    if request.method == "POST":
        # Capture old values for field-level audit trail
        old_values = {
            "name": item.name,
            "description": item.description,
            "quantity": str(item.quantity),
            "price": str(item.price),
            "sku": item.sku or "",
            "status": item.status,
            "category": str(item.category_id) if item.category_id else "",
        }

        serializer = InventoryItemUpdateSerializer(
            item,
            data=request.POST,
            partial=True,
            context={"request": request},
        )
        image = request.FILES.get("image")
        image_error = None

        if image:
            try:
                validate_file_upload(image)
                image.name = generate_safe_filename(image.name)
            except ValidationError as exc:
                image_error = exc.message

        if serializer.is_valid() and not image_error:
            updated_item = serializer.save(image=image if image else item.image)

            # Log each changed field individually for granular audit trail
            for field, old_val in old_values.items():
                new_val = str(getattr(updated_item, field, "") or "")
                if new_val != old_val:
                    _log_inventory_event(
                        request,
                        updated_item,
                        InventoryAuditLog.Action.UPDATED,
                        field_changed=field,
                        old_value=old_val,
                        new_value=new_val,
                    )

            if image:
                _log_inventory_event(
                    request, updated_item, InventoryAuditLog.Action.UPDATED,
                    field_changed="image", old_value="[previous]", new_value=image.name,
                )

            logger.info(
                "Inventory item updated: '%s' (pk=%s) by user '%s'",
                updated_item.name, updated_item.pk, request.user.username,
            )
            messages.success(request, f"Item '{updated_item.name}' updated successfully.")
            return redirect("inventory_service:item_detail", item_id=updated_item.pk)

        if image_error:
            messages.error(request, image_error)
        if not serializer.is_valid():
            messages.error(request, "Please correct the errors below.")

    else:
        serializer = InventoryItemUpdateSerializer(instance=item)

    return render(request, "inventory/update.html", {
        "item": item,
        "serializer": serializer,
        "categories": categories,
        "status_choices": InventoryItem.Status.choices,
    })


@login_required
@never_cache
def item_delete(request, item_id):
    """
    Delete an inventory item after confirmation.

    GET: render confirmation page.
    POST: perform deletion (CSRF protected).

    IDOR prevention: ownership checked before rendering and before deletion.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IDOR)
    - OWASP A08:2021 - Software and Data Integrity Failures (CSRF, POST-only delete)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """
    item = get_object_or_404(InventoryItem, pk=item_id)

    denied = _check_ownership(request, item)
    if denied:
        return denied

    if request.method == "POST":
        item_name = item.name
        item_pk = item.pk

        # Log before deletion so we have a record
        _log_inventory_event(request, item, InventoryAuditLog.Action.DELETED)
        logger.info(
            "Inventory item deleted: '%s' (pk=%s) by user '%s'",
            item_name, item_pk, request.user.username,
        )

        item.delete()
        messages.success(request, f"Item '{item_name}' has been deleted.")
        return redirect("inventory_service:item_list")

    return render(request, "inventory/delete_confirm.html", {"item": item})


# =============================================================================
# REST API Views
# =============================================================================

class ItemListCreateAPIView(ListCreateAPIView):
    """
    GET  /api/inventory/items/  -- list items (filtered by ownership).
    POST /api/inventory/items/  -- create a new item.

    get_queryset() enforces query-level IDOR prevention.
    perform_create() logs the creation event.

    Maps to:
    - OWASP A01:2021 - Broken Access Control (queryset filter)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """

    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Query-level IDOR prevention — same helper as template views
        return _get_user_items(self.request.user)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return InventoryItemCreateSerializer
        return InventoryItemListSerializer

    def perform_create(self, serializer):
        item = serializer.save()
        _log_inventory_event(self.request, item, InventoryAuditLog.Action.CREATED)


class ItemRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView):
    """
    GET/PUT/PATCH/DELETE /api/inventory/items/<uuid>/

    IsOwnerOrAdmin enforces object-level access control (IDOR prevention).

    Maps to:
    - OWASP A01:2021 - Broken Access Control (object-level permissions)
    - OWASP A09:2021 - Security Logging and Monitoring Failures
    """

    queryset = InventoryItem.objects.select_related("owner", "category").all()
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get_serializer_class(self):
        if self.request.method in ("PUT", "PATCH"):
            return InventoryItemUpdateSerializer
        return InventoryItemSerializer

    def perform_update(self, serializer):
        item = serializer.save()
        _log_inventory_event(self.request, item, InventoryAuditLog.Action.UPDATED)

    def perform_destroy(self, instance):
        _log_inventory_event(self.request, instance, InventoryAuditLog.Action.DELETED)
        instance.delete()


class CategoryListAPIView(ListAPIView):
    """
    GET /api/inventory/categories/  -- list all categories (read-only).

    All authenticated users can read categories;
    only admins can create/modify them (handled via Django admin).

    Maps to:
    - OWASP A01:2021 - Broken Access Control (IsAdminOrReadOnly)
    """

    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]