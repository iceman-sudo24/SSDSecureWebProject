from django.apps import AppConfig


class AuditServiceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "audit_service"
    verbose_name = "Audit Logging Service"