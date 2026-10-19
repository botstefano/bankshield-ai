import hashlib
import hmac
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import AuditLog, User

ITER = 240_000
bearer = HTTPBearer(auto_error=False)

PERMISSIONS = {
    "admin": {"*"},
    "analyst": {"analyze", "analysis:read_all", "alerts:read", "alerts:write", "dashboard", "reports", "intel:write"},
    "operator": {"analyze"},
    "auditor": {"audit:read", "reports", "dashboard", "alerts:read", "analysis:read_all"},
    "manager": {"dashboard", "reports", "alerts:read"},
}


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER)
    return f"pbkdf2${ITER}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def create_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.token_minutes)
    return jwt.encode({"sub": str(user.id), "role": user.role, "exp": exp}, settings.secret_key, algorithm="HS256")


def has_perm(role: str, perm: str) -> bool:
    p = PERMISSIONS.get(role, set())
    return "*" in p or perm in p


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not cred:
        raise HTTPException(401, "Autenticación requerida")
    try:
        data = jwt.decode(cred.credentials, settings.secret_key, algorithms=["HS256"])
        user = db.get(User, int(data["sub"]))
    except Exception:
        raise HTTPException(401, "Token inválido o expirado")
    if not user or not user.is_active:
        raise HTTPException(401, "Usuario inactivo")
    return user


def require(perm: str):
    def dep(user: User = Depends(current_user)) -> User:
        if not has_perm(user.role, perm):
            raise HTTPException(403, "Permiso insuficiente")  # verificación en backend
        return user
    return dep


def audit(db: Session, action: str, user_email: str = "", resource: str = "", outcome: str = "ok",
          request: Request | None = None, detail: str = "") -> None:
    db.add(AuditLog(user_email=user_email, action=action, resource=resource[:255], outcome=outcome,
                    ip=(request.client.host if request and request.client else ""), detail=detail[:1000]))
    db.commit()


# --- límites en memoria (suficiente para una instancia; usar Redis al escalar horizontalmente) ---
_lock = threading.Lock()
_hits: dict[str, list[float]] = {}
_fails: dict[str, list[float]] = {}


def rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    now = time.time()
    with _lock:
        h = [t for t in _hits.get(key, []) if now - t < 60]
        if len(h) >= settings.rate_limit_per_min:
            raise HTTPException(429, "Demasiadas solicitudes")
        h.append(now)
        _hits[key] = h


def login_blocked(key: str) -> bool:
    now = time.time()
    with _lock:
        f = [t for t in _fails.get(key, []) if now - t < 900]
        _fails[key] = f
        return len(f) >= 5


def login_failed(key: str) -> None:
    with _lock:
        _fails.setdefault(key, []).append(time.time())


def login_ok(key: str) -> None:
    with _lock:
        _fails.pop(key, None)


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.lower().strip()))
