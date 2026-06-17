# Secure Microservice-Based Web Application

A Django-based secure web application following OWASP Top 10, OWASP ASVS, and NIST SSDF guidelines.

## Architecture

Three logically separated microservices:

- **Authentication Service** (`auth_service`) — User registration, login, RBAC, profile management
- **Inventory Service** (`inventory_service`) — CRUD operations with ownership enforcement
- **Audit Logging Service** (`audit_service`) — Central security event logging and admin dashboard

## Security Controls

| Control | Implementation | OWASP Category |
|---|---|---|
| Input Validation | Whitelist regex + Django validators | A03: Injection |
| ORM Only | No raw SQL anywhere in codebase | A03: Injection |
| Password Hashing | Argon2 (primary) | A02: Cryptographic Failures |
| Secure Sessions | HttpOnly, Secure, SameSite=Strict | A05: Security Misconfiguration |
| CSRF Protection | Django CSRF middleware | A08: Data Integrity |
| RBAC | ADMIN/USER roles with decorators | A01: Broken Access Control |
| IDOR Prevention | UUID PKs + object-level permissions | A01: Broken Access Control |
| Safe Error Handling | Custom exception handler, no stack traces | A05: Security Misconfiguration |
| Secrets Management | .env file with python-dotenv | A02: Cryptographic Failures |
| Debug Disabled | DEBUG=False by default | A05: Security Misconfiguration |
| File Upload Security | MIME + extension + UUID + size limits | A04: Insecure Design |
| Output Escaping | Django auto-escaping + CSP headers | A03: XSS |
| Secure Logging | No sensitive data in logs, audit trail | A09: Logging Failures |

## Prerequisites

- Python 3.10+
- pip

## Setup & Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SSDSecureWebProject
   ```

2. **Create and activate a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create environment file**
   ```bash
   cp .env.example .env
   # Edit .env and set DJANGO_SECRET_KEY to a strong random key
   ```

5. **Run database migrations**
   ```bash
   python manage.py makemigrations auth_service inventory_service audit_service
   python manage.py migrate
   ```

6. **Create a superuser (admin)**
   ```bash
   python manage.py createsuperuser
   ```

7. **Set the superuser role to ADMIN**
   ```bash
   python manage.py shell -c "from auth_service.models import User; u = User.objects.get(username='YOUR_USERNAME'); u.role = 'ADMIN'; u.save()"
   ```

8. **Create sample categories (optional)**
   ```bash
   python manage.py shell -c "
   from inventory_service.models import Category
   Category.objects.create(name='Electronics', description='Electronic devices')
   Category.objects.create(name='Office Supplies', description='Office items')
   Category.objects.create(name='Furniture', description='Office furniture')
   "
   ```

9. **Run the development server**
   ```bash
   python manage.py runserver
   ```

10. **Access the application**
    - Login: http://localhost:8000/auth/login/
    - Register: http://localhost:8000/auth/register/
    - Inventory: http://localhost:8000/inventory/
    - Audit Dashboard (admin): http://localhost:8000/audit/
    - Django Admin: http://localhost:8000/admin/

## Docker Setup

```bash
# Copy environment file
cp .env.example .env
# Edit .env and set DJANGO_SECRET_KEY to a strong random key

# Build and run
docker-compose up --build

# Run migrations (in a separate terminal)
docker-compose exec web python manage.py makemigrations auth_service inventory_service audit_service
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Set superuser role to ADMIN
docker-compose exec web python manage.py shell -c "from auth_service.models import User; u = User.objects.get(username='YOUR_USERNAME'); u.role = 'ADMIN'; u.save()"
```

The Docker setup includes:
- Multi-stage build for minimal image size
- Non-root user (`appuser`) for container security
- Gunicorn WSGI server with 3 workers
- Health checks for container orchestration
- Named volumes for media uploads and logs

## URL Structure

| URL Pattern | Service | Access Level |
|---|---|---|
| `/auth/register/` | Auth Service | Public |
| `/auth/login/` | Auth Service | Public |
| `/auth/logout/` | Auth Service | Authenticated |
| `/auth/profile/` | Auth Service | Authenticated |
| `/inventory/` | Inventory Service | Authenticated |
| `/audit/` | Audit Service | Admin Only |
| `/api/auth/` | Auth REST API | Varies |
| `/api/inventory/` | Inventory REST API | Authenticated |
| `/api/audit/` | Audit REST API | Admin Only |

## Screenshots of the Web Application

## License

This project is developed for educational purposes.
