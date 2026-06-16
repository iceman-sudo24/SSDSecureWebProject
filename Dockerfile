# =============================================================================
# Dockerfile — Secure Microservice Django Application
# =============================================================================
# Multi-stage build for minimal production image.
#
# Security features:
# - Non-root user (appuser)
# - Minimal base image (python:3.12-slim)
# - No dev dependencies in production stage
# - libmagic1 for MIME type content validation
# - libargon2-dev for Argon2 password hashing
# - gunicorn with 3 workers for production serving
# - HEALTHCHECK for container orchestration
#
# Maps to:
# - OWASP A05:2021 - Security Misconfiguration
# - NIST SSDF PW.4 - Secure Coding Practices

# =============================================================================
# Stage 1: Builder — install dependencies
# =============================================================================
FROM python:3.12-slim AS builder

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libargon2-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy and install Python dependencies to a prefix
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# =============================================================================
# Stage 2: Production — minimal image
# =============================================================================
FROM python:3.12-slim

# Install runtime dependencies only (no gcc/dev headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libargon2-1 \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root user for security
# Maps to OWASP A05:2021 - Security Misconfiguration (least privilege)
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy application code
COPY . .

# Create required directories
RUN mkdir -p /app/logs /app/media/uploads /app/staticfiles && \
    chown -R appuser:appuser /app

# Collect static files
RUN python manage.py collectstatic --noinput 2>/dev/null || true

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Run with gunicorn — production WSGI server
# 3 workers, bind to all interfaces, 120s timeout
CMD ["gunicorn", "config.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]