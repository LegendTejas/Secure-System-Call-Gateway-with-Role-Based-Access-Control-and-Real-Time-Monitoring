"""
tests/conftest.py
Shared pytest fixtures — used by all test files.
Sets TESTING=true so all tests use an isolated in-memory DB.
"""

import os
os.environ["TESTING"] = "true"
os.environ["JWT_SECRET"] = "test_jwt_secret"

import pytest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database.models import init_db
from database.db     import get_connection
from auth_rbac.roles import load_permissions
from policy_engine.policy_loader import load_policies


@pytest.fixture(autouse=True)
def fresh_db():
    """
    Reinitialize the DB before every test.
    We clear the tables to ensure total isolation.
    """
    conn = get_connection()
    cursor = conn.cursor()
    # Disable foreign keys temporarily to drop/clear easily
    cursor.execute("PRAGMA foreign_keys = OFF")
    tables = ["users", "syscall_logs", "policies", "roles", "sessions", "otps"]
    for table in tables:
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
    conn.commit()
    conn.close()

    init_db()
    load_permissions()
    load_policies()
    yield
    # Teardown: close any lingering connections
    conn = get_connection()
    conn.close()


@pytest.fixture
def admin_token():
    """Register an admin user and return their JWT token."""
    from auth_rbac.auth_controller import register_user, login_user
    register_user("test_admin", "AdminPass1", "admin")
    result = login_user("test_admin", "AdminPass1")
    return result["token"]


@pytest.fixture
def developer_token():
    """Register a developer user and return their JWT token."""
    from auth_rbac.auth_controller import register_user, login_user
    register_user("test_dev", "DevPass1", "developer")
    result = login_user("test_dev", "DevPass1")
    return result["token"]


@pytest.fixture
def guest_token():
    """Register a guest user and return their JWT token."""
    from auth_rbac.auth_controller import register_user, login_user
    register_user("test_guest", "GuestPass1", "guest")
    result = login_user("test_guest", "GuestPass1")
    return result["token"]


@pytest.fixture
def guest_user_id():
    """Return the DB id of the registered guest user."""
    from auth_rbac.auth_controller import register_user
    register_user("test_guest", "GuestPass1", "guest")
    conn = get_connection()
    row  = conn.execute("SELECT id FROM users WHERE username='test_guest'").fetchone()
    conn.close()
    return row["id"]
