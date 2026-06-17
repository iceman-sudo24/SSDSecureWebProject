"""
Management command to seed the database with a default admin account,
a test user, sample categories, and sample inventory items.

Usage:
    python manage.py seed_data

This command is idempotent — it skips creation if the data already exists.
Default credentials are for development/evaluation purposes only.

Security Note:
    Passwords are hashed using the configured password hasher (Argon2).
    Default credentials should be changed immediately in any non-development environment.

Maps to:
    - OWASP A05:2021 - Security Misconfiguration (development convenience)
    - NIST SSDF PW.4 - Secure Coding Practices
"""

import logging

from django.core.management.base import BaseCommand
from django.db import IntegrityError

from auth_service.models import Role, User, UserProfile
from inventory_service.models import Category, InventoryItem

logger = logging.getLogger("django")

# Default credentials — development/evaluation only
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@12345678"
ADMIN_EMAIL = "admin@example.com"

TEST_USERNAME = "testuser"
TEST_PASSWORD = "Test@123456789"
TEST_EMAIL = "testuser@example.com"


class Command(BaseCommand):
    help = (
        "Seed the database with a default admin account, a test user, "
        "sample categories, and sample inventory items. "
        "Intended for development and evaluation purposes."
    )

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("Seeding database..."))

        # ── Step 1: Create admin user ──────────────────────────────────
        admin_created = self._create_user(
            username=ADMIN_USERNAME,
            password=ADMIN_PASSWORD,
            email=ADMIN_EMAIL,
            role=Role.ADMIN,
            is_staff=True,
            is_superuser=True,
            first_name="Admin",
            last_name="User",
        )

        # ── Step 2: Create test (normal) user ──────────────────────────
        test_created = self._create_user(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            email=TEST_EMAIL,
            role=Role.USER,
            is_staff=False,
            is_superuser=False,
            first_name="Test",
            last_name="User",
        )

        # ── Step 3: Create sample categories ───────────────────────────
        categories_created = self._create_categories()

        # ── Step 4: Create sample inventory items ─────────────────────
        admin_items_created = self._create_admin_inventory_items()
        test_items_created = self._create_test_inventory_items()
        items_created = admin_items_created + test_items_created

        # ── Summary ────────────────────────────────────────────────────
        self.stdout.write("")
        if admin_created:
            self.stdout.write(self.style.SUCCESS("  Admin user created."))
            self.stdout.write(f"    Username : {ADMIN_USERNAME}")
            self.stdout.write(f"    Password : {ADMIN_PASSWORD}")
            self.stdout.write(f"    Email    : {ADMIN_EMAIL}")
            self.stdout.write(f"    Role     : ADMIN")
        else:
            self.stdout.write(
                self.style.WARNING(f"  Admin user '{ADMIN_USERNAME}' already exists — skipped.")
            )

        self.stdout.write("")
        if test_created:
            self.stdout.write(self.style.SUCCESS("  Test user created."))
            self.stdout.write(f"    Username : {TEST_USERNAME}")
            self.stdout.write(f"    Password : {TEST_PASSWORD}")
            self.stdout.write(f"    Role     : USER")
        else:
            self.stdout.write(
                self.style.WARNING(f"  Test user '{TEST_USERNAME}' already exists — skipped.")
            )

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"  {categories_created} categories created."))
        self.stdout.write(self.style.SUCCESS(
            f"  {admin_items_created} admin items + {test_items_created} test items created."
        ))

        self.stdout.write("")
        self.stdout.write(self.style.WARNING(
            "  SECURITY WARNING: Default credentials are for development/evaluation only."
        ))
        self.stdout.write(self.style.WARNING(
            "  Change all passwords before any non-development deployment."
        ))
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Seeding complete."))

    # ── Helper methods ──────────────────────────────────────────────────

    def _create_user(self, username, password, email, role, is_staff,
                     is_superuser, first_name="", last_name=""):
        """Create a user with the given parameters. Returns True if created."""
        if User.objects.filter(username=username).exists():
            return False

        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,  # Hashed via set_password → Argon2
                first_name=first_name,
                last_name=last_name,
                role=role,
                is_staff=is_staff,
                is_superuser=is_superuser,
            )
            UserProfile.objects.create(user=user)
            logger.info("Seed data: created user '%s' (role=%s)", username, role)
            return True
        except IntegrityError:
            return False

    def _create_categories(self):
        """Create sample categories. Returns count of categories created."""
        category_data = [
            {"name": "Electronics", "description": "Electronic devices and accessories"},
            {"name": "Office Supplies", "description": "Office stationery and consumables"},
            {"name": "Furniture", "description": "Office and workspace furniture"},
        ]

        created_count = 0
        for data in category_data:
            obj, created = Category.objects.get_or_create(
                name=data["name"],
                defaults={"description": data["description"]},
            )
            if created:
                created_count += 1

        return created_count

    def _create_admin_inventory_items(self):
        """Create sample inventory items owned by the admin user. Returns count created."""
        try:
            admin = User.objects.get(username=ADMIN_USERNAME)
        except User.DoesNotExist:
            return 0

        electronics = Category.objects.filter(name="Electronics").first()
        office = Category.objects.filter(name="Office Supplies").first()
        furniture = Category.objects.filter(name="Furniture").first()

        item_data = [
            {
                "name": "Dell 24 Monitor",
                "description": "Dell 24-inch Full HD IPS monitor with thin bezels.",
                "category": electronics,
                "quantity": 25,
                "price": "189.99",
                "sku": "DELL-24-MON",
                "status": InventoryItem.Status.ACTIVE,
            },
            {
                "name": "A4 Copy Paper (500 sheets)",
                "description": "Standard A4 white copy paper, 80gsm, 500 sheets per ream.",
                "category": office,
                "quantity": 150,
                "price": "5.50",
                "sku": "OFF-A4-PAPER",
                "status": InventoryItem.Status.ACTIVE,
            },
            {
                "name": "Ergonomic Office Chair",
                "description": "Adjustable ergonomic office chair with lumbar support and mesh back.",
                "category": furniture,
                "quantity": 8,
                "price": "299.00",
                "sku": "FURN-ERG-CHAIR",
                "status": InventoryItem.Status.ACTIVE,
            },
        ]

        return self._bulk_create_items(admin, item_data)

    def _create_test_inventory_items(self):
        """Create sample inventory items owned by the test user. Returns count created."""
        try:
            test_user = User.objects.get(username=TEST_USERNAME)
        except User.DoesNotExist:
            return 0

        electronics = Category.objects.filter(name="Electronics").first()
        office = Category.objects.filter(name="Office Supplies").first()

        item_data = [
            {
                "name": "Wireless Keyboard",
                "description": "Logitech K380 multi-device Bluetooth keyboard.",
                "category": electronics,
                "quantity": 12,
                "price": "39.99",
                "sku": "ELEC-WL-KB",
                "status": InventoryItem.Status.ACTIVE,
            },
            {
                "name": "LED Desk Lamp",
                "description": "Adjustable LED desk lamp with USB charging port.",
                "category": office,
                "quantity": 6,
                "price": "24.50",
                "sku": "OFF-LED-LAMP",
                "status": InventoryItem.Status.ACTIVE,
            },
        ]

        return self._bulk_create_items(test_user, item_data)

    def _bulk_create_items(self, owner, item_data):
        """Create inventory items for a given owner. Returns count created."""
        created_count = 0
        for data in item_data:
            obj, created = InventoryItem.objects.get_or_create(
                sku=data["sku"],
                defaults={
                    "owner": owner,
                    "name": data["name"],
                    "description": data["description"],
                    "category": data["category"],
                    "quantity": data["quantity"],
                    "price": data["price"],
                    "status": data["status"],
                },
            )
            if created:
                created_count += 1

        return created_count
