# Secure Microservice-Based Inventory Asset Management Web Application 

A Django-based secure web application following OWASP Top 10, OWASP ASVS, and NIST SSDF guidelines. 

This is the second repository made for this project due to issues with the previous repository in terms of proper conventions and the learning process.

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

6. **Seed the database (recommended)**
   ```bash
   python manage.py seed_data
   ```
   This creates a default admin account, a test user, sample categories, and 3 sample inventory items.

   | Account     | Username   | Password         | Role  |
   |-------------|------------|------------------|-------|
   | Admin       | `admin`    | `Admin@12345678` | ADMIN |
   | Test User   | `testuser` | `Test@123456789` | USER  |

   > **Security Note:** Default credentials are for development/evaluation only. Change all passwords before any non-development deployment.

   **Alternatively**, create a superuser manually:
   ```bash
   python manage.py createsuperuser
   # Then set the role to ADMIN:
   python manage.py shell -c "from auth_service.models import User; u = User.objects.get(username='YOUR_USERNAME'); u.role = 'ADMIN'; u.save()"
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

8. **Access the application**
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
docker-compose exec web python manage.py seed_data

# Alternatively, create a superuser manually:
# docker-compose exec web python manage.py createsuperuser
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
### Register
<img width="1680" height="945" alt="Screenshot 2026-06-18 at 1 45 22 PM" src="https://github.com/user-attachments/assets/92115afe-048d-49ae-afcc-fde7c40ef067" />

### Login 
<img width="1679" height="946" alt="Screenshot 2026-06-18 at 1 44 51 PM" src="https://github.com/user-attachments/assets/0a85ae2f-a170-4737-9d84-907bf662abde" />

### Inventory 
<img width="1680" height="944" alt="Screenshot 2026-06-18 at 1 51 52 PM" src="https://github.com/user-attachments/assets/595282e1-0f13-4c57-a500-8a665d8ad651" />

### Add Item
<img width="1680" height="944" alt="Screenshot 2026-06-18 at 1 51 58 PM" src="https://github.com/user-attachments/assets/eabee833-dcaa-47ac-b274-056506af66c2" />

### Edit Item
<img width="1680" height="946" alt="Screenshot 2026-06-18 at 1 56 29 PM" src="https://github.com/user-attachments/assets/3ac3ae28-d4bd-4561-a426-bc1e102322c4" />

### Profile
<img width="1680" height="942" alt="Screenshot 2026-06-18 at 1 54 08 PM" src="https://github.com/user-attachments/assets/b9d5d343-9409-47eb-989f-1efd063a4d84" />

### Admin Inventory 
<img width="1680" height="943" alt="Screenshot 2026-06-18 at 1 54 23 PM" src="https://github.com/user-attachments/assets/40c296b3-2d11-43b9-a0ac-efc570cc3fa1" />

### Admin Audit Dashboard
<img width="1677" height="939" alt="Screenshot 2026-06-18 at 1 54 32 PM" src="https://github.com/user-attachments/assets/bed206f3-5611-48ac-ae9c-287fd8b7d896" />
<img width="1680" height="939" alt="Screenshot 2026-06-18 at 1 54 41 PM" src="https://github.com/user-attachments/assets/a55deba9-ed7b-4daf-acf4-fff90b2c43b8" />



## License

This project is developed for educational purposes.
