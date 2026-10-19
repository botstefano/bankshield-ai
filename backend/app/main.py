import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .api.routes import router
from .config import settings
from .db import Base, SessionLocal, engine
from .ml import model as ml
from .models import User
from .security import get_user_by_email, hash_password
from .services import threat_intel

log = logging.getLogger("bankshield")
logging.basicConfig(level=logging.INFO)

DEMO_USERS = [("analyst@bankshield.local", "analyst"), ("operator@bankshield.local", "operator"),
              ("auditor@bankshield.local", "auditor"), ("manager@bankshield.local", "manager")]
DEMO_INDICATORS = ["http://bcp-seguro-acceso.example-phish.test/login", "https://viabcp-verifica.example-phish.test/clave"]


def bootstrap() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not get_user_by_email(db, settings.admin_email):
            pw = settings.admin_password or secrets.token_urlsafe(14)
            if not settings.admin_password:
                log.warning("ADMIN_PASSWORD no definido. Contraseña generada para %s: %s", settings.admin_email, pw)
            db.add(User(email=settings.admin_email.lower(), full_name="Administrador", role="admin", password_hash=hash_password(pw)))
        if settings.seed_demo:
            demo_pw = "Demo#2026-Cambiar"
            for email, role in DEMO_USERS:
                if not get_user_by_email(db, email):
                    db.add(User(email=email, full_name=f"Demo {role}", role=role, password_hash=hash_password(demo_pw)))
            for u in DEMO_INDICATORS:
                threat_intel.add_indicator(db, u, "demo")
            log.warning("SEED_DEMO activo: cuentas demo con contraseña conocida. NO usar en producción.")
        db.commit()
    ml.load(train_if_missing=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.env == "production" and settings.secret_key == "dev-insecure-change-me":
        raise RuntimeError("Define SECRET_KEY en producción")
    bootstrap()
    yield


app = FastAPI(title="BankShield AI", version="1.0.0", lifespan=lifespan,
              description="Plataforma de detección de phishing en procesos bancarios.")
app.include_router(router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp


STATIC = os.path.abspath(settings.static_dir)
if os.path.isdir(STATIC):
    if os.path.isdir(os.path.join(STATIC, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(STATIC, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "No encontrado"}, status_code=404)
        f = os.path.abspath(os.path.join(STATIC, full_path))
        if f.startswith(STATIC + os.sep) and os.path.isfile(f):
            return FileResponse(f)
        return FileResponse(os.path.join(STATIC, "index.html"))
