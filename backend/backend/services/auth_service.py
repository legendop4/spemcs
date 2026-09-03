"""Authentication helpers — JWT token management and password hashing."""

import logging
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.models.user import User

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    try:
        if not plain_password or not hashed_password:
            return False
        plain_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(plain_bytes, hash_bytes)
    except Exception as e:
        logger.warning(f"Password verification failed: {e}")
        return False


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Extract and validate the current user from JWT token.
    Returns None if no token is provided (for gradual auth adoption)."""
    if not credentials:
        return None
    
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        user = db.query(User).filter(User.user_id == user_id).first()
        return user
    except JWTError:
        return None


def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Require a valid JWT token. Raises 401 if not authenticated."""
    user = get_current_user(credentials, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(allowed_roles: list[str]):
    """Require an authenticated user having at least one of the specified roles.
    Raises 401 if unauthenticated, 403 if authenticated but unauthorized."""
    def _role_checker(user: User = Depends(require_auth)) -> User:
        user_role = (user.role or "").lower()
        normalized_allowed = [r.lower() for r in allowed_roles]
        if user_role not in normalized_allowed:
            logger.warning(
                "Access forbidden: User %s (role: %s) requested endpoint requiring %s",
                user.username, user.role, allowed_roles
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires one of roles: {', '.join(allowed_roles)}",
            )
        return user
    return _role_checker


# --- M8 Cryptographically Authenticated Device Tokens (HMAC-SHA256) ---

def create_device_token(
    hardware_uuid: str,
    token_id: Optional[str] = None,
    ttl_seconds: int = 2592000,  # 30 days
) -> str:
    """Issue a cryptographically authenticated enrollment token for a hardware_uuid using HMAC-SHA256."""
    import base64
    import hashlib
    import hmac
    import json
    import secrets
    import uuid

    payload = {
        "token_id": token_id or str(uuid.uuid4()),
        "hardware_uuid": hardware_uuid,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(seconds=ttl_seconds)).timestamp()),
        "nonce": secrets.token_hex(16),
        "roles": ["endpoint"],
    }

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    sig = hmac.new(settings.DEVICE_TOKEN_SECRET.encode("utf-8"), payload_bytes, hashlib.sha256).digest()

    token = f"{base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')}.{base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')}"
    return token


def verify_device_token(
    token_str: str,
    expected_hardware_uuid: Optional[str] = None,
) -> Optional[dict]:
    """Verify an HMAC-SHA256 device token.
    Validates signature, expiration, and optional hardware_uuid binding in constant time.
    Returns decoded token payload if valid, None otherwise."""
    import base64
    import hashlib
    import hmac
    import json

    if not token_str or "." not in token_str:
        return None

    try:
        parts = token_str.split(".", 1)
        if len(parts) != 2:
            return None

        payload_b64, sig_b64 = parts[0], parts[1]

        # Add padding back if necessary
        payload_rem = len(payload_b64) % 4
        if payload_rem:
            payload_b64 += "=" * (4 - payload_rem)
        sig_rem = len(sig_b64) % 4
        if sig_rem:
            sig_b64 += "=" * (4 - sig_rem)

        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        sig_bytes = base64.urlsafe_b64decode(sig_b64.encode("ascii"))

        expected_sig = hmac.new(settings.DEVICE_TOKEN_SECRET.encode("utf-8"), payload_bytes, hashlib.sha256).digest()

        # Constant-time comparison
        if not hmac.compare_digest(sig_bytes, expected_sig):
            logger.warning("Device token HMAC signature verification failed.")
            return None

        payload = json.loads(payload_bytes.decode("utf-8"))

        # Expiration check
        exp = payload.get("exp")
        if not exp or int(datetime.utcnow().timestamp()) >= int(exp):
            logger.warning("Device token has expired.")
            return None

        # Hardware UUID match check if requested
        if expected_hardware_uuid:
            token_hw = payload.get("hardware_uuid", "")
            if not hmac.compare_digest(token_hw.encode("utf-8"), expected_hardware_uuid.encode("utf-8")):
                logger.warning(
                    "Device token hardware_uuid mismatch: token holds '%s' but requested for '%s'",
                    token_hw, expected_hardware_uuid
                )
                return None

        return payload
    except Exception as exc:
        logger.warning(f"Device token verification error: {exc}")
        return None
