import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import List

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import AccessEvent, AuditLog, User

SECRET_KEY = os.getenv("SECRET_KEY", "aramana-dev-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = "aramana_static_demo_salt"
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return dk.hex()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hmac.compare_digest(hash_password(plain_password), hashed_password)


def create_access_token(user_id: int, role: str, email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "role": role, "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def log_audit(db: Session, actor_id: int, action: str, target_table: str, target_id: str, details: dict):
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_table=target_table,
        target_id=str(target_id),
        details=details,
    )
    db.add(entry)
    db.commit()


def require_roles(allowed_roles: List[str], resource_type: str):
    """
    RBAC dependency that enforces role-based access AND logs every access attempt
    (authorized or unauthorized) into access_events for Scenario 4 detection.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        is_allowed = current_user.role in allowed_roles
        event = AccessEvent(
            user_id=current_user.id,
            user_role=current_user.role,
            endpoint=str(request.url.path),
            resource_type=resource_type,
            action=request.method,
            is_authorized=is_allowed,
            ip_address=request.client.host if request.client else "127.0.0.1",
        )
        db.add(event)
        db.commit()

        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not authorized to access {resource_type}. Event logged.",
            )
        return current_user

    return role_checker
