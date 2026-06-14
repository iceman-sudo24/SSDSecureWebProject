from django.apps import AppConfig


class InventoryServiceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "inventory_service"
    verbose_name = "Inventory Service"