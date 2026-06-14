"""
Inventory Service URL configuration (template views).

All routes require authentication (enforced in each view via @login_required).
UUIDs are used for item IDs to prevent sequential ID enumeration (OWASP A01).

Maps to:
- OWASP A01:2021 - Broken Access Control (UUID route parameters)
"""

from django.urls import path

from inventory_service import views

app_name = "inventory_service"

urlpatterns = [
    path("", views.item_list, name="item_list"),
    path("create/", views.item_create, name="item_create"),
    path("<uuid:item_id>/", views.item_detail, name="item_detail"),
    path("<uuid:item_id>/update/", views.item_update, name="item_update"),
    path("<uuid:item_id>/delete/", views.item_delete, name="item_delete"),
]