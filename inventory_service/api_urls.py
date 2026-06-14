"""
Inventory Service REST API URL configuration.

All endpoints require authentication (enforced via DRF permission_classes).
UUID route parameters prevent sequential ID enumeration (OWASP A01).

Maps to:
- OWASP A01:2021 - Broken Access Control (UUID route parameters)
"""

from django.urls import path

from inventory_service.views import (
    CategoryListAPIView,
    ItemListCreateAPIView,
    ItemRetrieveUpdateDestroyAPIView,
)

app_name = "inventory_api"

urlpatterns = [
    path("items/", ItemListCreateAPIView.as_view(), name="item_list"),
    path("items/<uuid:pk>/", ItemRetrieveUpdateDestroyAPIView.as_view(), name="item_detail"),
    path("categories/", CategoryListAPIView.as_view(), name="category_list"),
]