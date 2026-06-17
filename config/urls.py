"""Root URL configuration for the Secure Microservice Web Application."""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect
from config.security import csrf_failure_view


def root_redirect(request):
    """Redirect root URL to login page."""
    return redirect("auth_service:login")


urlpatterns = [
    path("", root_redirect, name="root"),
    path(settings.ADMIN_URL, admin.site.urls),
    path("auth/", include("auth_service.urls", namespace="auth_service")),
    path("inventory/", include("inventory_service.urls", namespace="inventory_service")),
    path("audit/", include("audit_service.urls", namespace="audit_service")),
    path("api/auth/", include("auth_service.api_urls", namespace="auth_api")),
    path("api/inventory/", include("inventory_service.api_urls", namespace="inventory_api")),
    path("api/audit/", include("audit_service.api_urls", namespace="audit_api")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

handler403 = csrf_failure_view


def custom_404(request, exception):
    """Custom 404 page - no information disclosure."""
    from django.shortcuts import render
    return render(request, "errors/404.html", status=404)


def custom_500(request):
    """Custom 500 page - no stack traces exposed."""
    from django.shortcuts import render
    return render(request, "errors/500.html", status=500)


def custom_400(request, exception):
    """Custom 400 page - safe error message."""
    from django.shortcuts import render
    return render(request, "errors/400.html", status=400)


handler404 = custom_404
handler500 = custom_500
handler400 = custom_400
