"""Tests for initial administrator seeding and password management.

Validates:
1. Seed Behavior:
   - Fresh DB + INITIAL_ADMIN_PASSWORD creates the admin account.
   - Existing admin + different INITIAL_ADMIN_PASSWORD preserves the existing password hash.
   - Application/ECS restart simulation (repeated ensure_demo_admin calls) does not modify the password.
   - When INITIAL_ADMIN_PASSWORD is unset, startup does not create an admin with a hardcoded fallback.
   - No plaintext password appears in log output.

2. Password Change API:
   - Authenticated operator can change their password with valid current credentials.
   - Old password no longer authenticates after rotation.
   - New password authenticates successfully after rotation.
   - Wrong current password is rejected with HTTP 400.
   - New password identical to current password is rejected.
   - New password shorter than 8 characters is rejected with HTTP 422.
   - Unauthenticated requests are rejected with HTTP 401.
   - AuditLog record is persisted with action="PASSWORD_CHANGED".
   - Password values are never leaked in response bodies or log messages.
"""

from __future__ import annotations

import logging
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.audit_log import AuditLog
from backend.models.user import User, UserRole
from backend.seed.seed_demo_admin import (
    INITIAL_ADMIN_USERNAME,
    ensure_demo_admin,
)
from backend.services.auth_service import (
    create_access_token,
    hash_password,
    verify_password,
)


def _unique_password(prefix: str = "P@ss") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}!"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Seed Behavior Tests
# ─────────────────────────────────────────────────────────────────────────────


def test_fresh_db_with_initial_admin_password_creates_admin(monkeypatch, caplog):
    """When no admin exists and INITIAL_ADMIN_PASSWORD is set, ensure_demo_admin creates it."""
    test_password = _unique_password("InitSecret")
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", test_password)

    with SessionLocal() as db:
        # Clean up any existing admin in test database
        db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).delete()
        db.commit()

        with caplog.at_level(logging.INFO):
            ensure_demo_admin(db)

        admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
        assert admin is not None
        assert admin.role == UserRole.ADMIN.value
        assert verify_password(test_password, admin.password_hash)

        # Verification: Plaintext password is NEVER logged
        assert test_password not in caplog.text


def test_existing_admin_password_preserved_even_if_initial_password_differs(monkeypatch):
    """If an admin account already exists, ensure_demo_admin MUST NOT modify its password."""
    original_password = _unique_password("OrigSecret")
    different_password = _unique_password("DiffSecret")

    with SessionLocal() as db:
        # Ensure admin exists with original_password
        admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                name="Existing Admin",
                username=INITIAL_ADMIN_USERNAME,
                email="admin-test@example.com",
                password=hash_password(original_password),
                password_hash=hash_password(original_password),
                role=UserRole.ADMIN.value,
                avatar_color="#D89400",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
        else:
            orig_hash = hash_password(original_password)
            admin.password = orig_hash
            admin.password_hash = orig_hash
            db.commit()
            db.refresh(admin)

        original_hash = admin.password_hash

        # Now simulate startup with a DIFFERENT INITIAL_ADMIN_PASSWORD
        monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", different_password)
        ensure_demo_admin(db)

        # Reload from database and verify the original password and hash were NOT changed
        db.expire_all()
        reloaded_admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
        assert reloaded_admin.password_hash == original_hash
        assert verify_password(original_password, reloaded_admin.password_hash)
        assert not verify_password(different_password, reloaded_admin.password_hash)


def test_application_restart_simulation_never_resets_password(monkeypatch):
    """Simulate repeated container/ECS task restarts; existing password must stay intact."""
    user_password = _unique_password("UserRotated")

    with SessionLocal() as db:
        admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
        user_hash = hash_password(user_password)
        admin.password = user_hash
        admin.password_hash = user_hash
        db.commit()
        db.refresh(admin)
        saved_hash = admin.password_hash

        # Simulate 5 consecutive container restarts with random INITIAL_ADMIN_PASSWORD values
        for i in range(5):
            monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", _unique_password(f"Restart{i}"))
            ensure_demo_admin(db)

            db.expire_all()
            current_admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
            assert current_admin.password_hash == saved_hash
            assert verify_password(user_password, current_admin.password_hash)


def test_empty_initial_admin_password_skips_creation_without_fallback(monkeypatch, caplog):
    """When INITIAL_ADMIN_PASSWORD is empty, no admin is created and no hardcoded fallback is used."""
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "")

    with SessionLocal() as db:
        db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).delete()
        db.commit()

        with caplog.at_level(logging.INFO):
            ensure_demo_admin(db)

        admin = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
        assert admin is None
        assert "skipping initial admin creation" in caplog.text


# ─────────────────────────────────────────────────────────────────────────────
# 2. Password Change API Tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    return TestClient(app)


def test_password_change_requires_authentication(client):
    """POST /api/auth/change-password without token returns 401."""
    resp = client.post(
        "/api/auth/change-password",
        json={"current_password": "anyPassword123!", "new_password": "newPassword123!"},
    )
    assert resp.status_code == 401


def test_password_change_rejects_incorrect_current_password(client):
    """POST /api/auth/change-password with wrong current password returns 400."""
    correct_password = _unique_password("CurrentPwd")
    wrong_password = _unique_password("WrongPwd")
    new_password = _unique_password("NewValidPwd")

    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "test_change_user_1").first()
        if not user:
            user = User(
                name="Test Change User",
                username="test_change_user_1",
                email="change1@example.com",
                password=hash_password(correct_password),
                password_hash=hash_password(correct_password),
                role=UserRole.ADMIN.value,
                avatar_color="#D89400",
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        token = create_access_token(data={"sub": str(user.user_id), "username": user.username, "role": user.role})

    resp = client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": wrong_password, "new_password": new_password},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Incorrect current password"


def test_password_change_rejects_identical_new_password(client):
    """POST /api/auth/change-password with identical new password returns 400."""
    same_password = _unique_password("SamePwd")

    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "test_change_user_same").first()
        if not user:
            user = User(
                name="Test Same User",
                username="test_change_user_same",
                email="same@example.com",
                password=hash_password(same_password),
                password_hash=hash_password(same_password),
                role=UserRole.ADMIN.value,
                avatar_color="#D89400",
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        token = create_access_token(data={"sub": str(user.user_id), "username": user.username, "role": user.role})

    resp = client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": same_password, "new_password": same_password},
    )
    assert resp.status_code == 400
    assert "different from current password" in resp.json()["detail"]


def test_password_change_rejects_short_new_password(client):
    """POST /api/auth/change-password with < 8 chars returns 422."""
    current_password = _unique_password("ValidCur")

    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "test_change_user_short").first()
        if not user:
            user = User(
                name="Test Short User",
                username="test_change_user_short",
                email="short@example.com",
                password=hash_password(current_password),
                password_hash=hash_password(current_password),
                role=UserRole.ADMIN.value,
                avatar_color="#D89400",
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        token = create_access_token(data={"sub": str(user.user_id), "username": user.username, "role": user.role})

    resp = client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": current_password, "new_password": "short"},
    )
    assert resp.status_code == 422


def test_successful_password_change_flow(client, caplog):
    """End-to-end: change password, verify old fails, verify new succeeds, verify audit log."""
    old_password = _unique_password("OldWorking")
    new_password = _unique_password("NewWorking")
    username = f"user_e2e_{uuid.uuid4().hex[:8]}"

    with SessionLocal() as db:
        user = User(
            name="E2E Change User",
            username=username,
            email=f"{username}@example.com",
            password=hash_password(old_password),
            password_hash=hash_password(old_password),
            role=UserRole.ADMIN.value,
            avatar_color="#D89400",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.user_id

    # 1. Login with old password succeeds
    login1 = client.post("/api/auth/login", json={"username": username, "password": old_password})
    assert login1.status_code == 200
    token1 = login1.json()["access_token"]

    # 2. Change password with token1
    with caplog.at_level(logging.INFO):
        change_resp = client.post(
            "/api/auth/change-password",
            headers={"Authorization": f"Bearer {token1}"},
            json={"current_password": old_password, "new_password": new_password},
        )
    assert change_resp.status_code == 200
    assert change_resp.json()["status"] == "ok"

    # Verify neither password is in response body or logs
    assert old_password not in change_resp.text
    assert new_password not in change_resp.text
    assert old_password not in caplog.text
    assert new_password not in caplog.text

    # 3. Old password now FAILS login
    login_old = client.post("/api/auth/login", json={"username": username, "password": old_password})
    assert login_old.status_code == 401

    # 4. New password SUCCEEDS login
    login_new = client.post("/api/auth/login", json={"username": username, "password": new_password})
    assert login_new.status_code == 200
    assert "access_token" in login_new.json()

    # 5. Audit log entry is present in DB
    with SessionLocal() as db:
        audit = (
            db.query(AuditLog)
            .filter(AuditLog.user_id == user_id, AuditLog.action == "PASSWORD_CHANGED")
            .first()
        )
        assert audit is not None
        assert audit.entity_type == "user"
        assert audit.entity_id == str(user_id)
        assert audit.details == {"username": username}
