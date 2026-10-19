from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import schemas
from ..agents.explainer import explain
from ..config import settings
from ..db import get_db
from ..ml import model as ml
from ..models import Alert, Analysis, AuditLog, ThreatIndicator, User
from ..security import (audit, create_token, current_user, get_user_by_email, has_perm, hash_password,
                        login_blocked, login_failed, login_ok, rate_limit, require, verify_password)
from ..services import reports, risk, threat_intel
from ..services.url_features import BlockedTarget, InvalidUrl

router = APIRouter(prefix="/api/v1")
ALERT_LEVELS = {"alto", "critico"}


# ---------------- salud ----------------
@router.get("/health", tags=["salud"])
def health():
    return {"status": "ok"}


@router.get("/ready", tags=["salud"])
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        db_ok = True
    except Exception:
        db_ok = False
    model_ok = ml.metadata() != {}
    if not db_ok:
        raise HTTPException(503, {"database": db_ok, "model": model_ok})
    return {"status": "ready", "database": db_ok, "model": model_ok, "model_version": ml.version(),
            "model_is_demo": bool(ml.metadata().get("warning"))}


# ---------------- auth ----------------
@router.post("/auth/login", tags=["auth"])
def login(body: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    key = f"{(request.client.host if request.client else '')}|{body.email.lower()}"
    if login_blocked(key):
        raise HTTPException(429, "Demasiados intentos. Espera unos minutos.")
    user = get_user_by_email(db, body.email)
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        login_failed(key)
        audit(db, "login", body.email, outcome="fail", request=request)
        raise HTTPException(401, "Credenciales inválidas")  # mensaje genérico
    login_ok(key)
    audit(db, "login", user.email, request=request)
    return {"access_token": create_token(user), "token_type": "bearer",
            "user": schemas.UserOut.model_validate(user).model_dump()}


@router.get("/auth/me", response_model=schemas.UserOut, tags=["auth"])
def me(user: User = Depends(current_user)):
    return user


# ---------------- análisis ----------------
def _notify(payload: dict):
    if not settings.n8n_webhook_url:
        return
    try:
        httpx.post(settings.n8n_webhook_url, json=payload, timeout=5,
                   headers={"X-Webhook-Secret": settings.n8n_webhook_secret})
    except Exception:
        pass  # n8n caído no debe afectar al análisis


def _run_analysis(db: Session, req: schemas.AnalyzeRequest, user: User, bg: BackgroundTasks | None) -> Analysis:
    result = risk.assess(db, req.url)
    result["explanation"] = explain(result)
    a = Analysis(source_app=req.source_app, operation=req.operation, correlation_id=req.correlation_id,
                 user_id=user.id, **result)
    db.add(a)
    db.flush()
    if a.level in ALERT_LEVELS:
        alert = Alert(analysis_id=a.id, level=a.level)
        db.add(alert)
        db.flush()
        if bg:
            bg.add_task(_notify, {"event": "high_risk_alert", "alert_id": alert.id, "analysis_id": a.id,
                                  "level": a.level, "score": a.score, "domain": a.domain,
                                  "recommendation": a.recommendation})
    db.commit()
    return a


@router.post("/analyze", response_model=schemas.AnalysisOut, tags=["análisis"], dependencies=[Depends(rate_limit)])
def analyze(req: schemas.AnalyzeRequest, bg: BackgroundTasks, request: Request,
            user: User = Depends(require("analyze")), db: Session = Depends(get_db)):
    try:
        a = _run_analysis(db, req, user, bg)
    except (InvalidUrl, BlockedTarget) as exc:
        audit(db, "analyze", user.email, outcome="rejected", request=request, detail=str(exc))
        raise HTTPException(422, str(exc))
    return a


@router.post("/analyze/batch", tags=["análisis"], dependencies=[Depends(rate_limit)])
def analyze_batch(body: schemas.BatchRequest, bg: BackgroundTasks,
                  user: User = Depends(require("analyze")), db: Session = Depends(get_db)):
    if len(body.items) > settings.batch_max:
        raise HTTPException(413, f"Máximo {settings.batch_max} URL por lote")
    out = []
    for item in body.items:
        try:
            a = _run_analysis(db, item, user, bg)
            out.append({"ok": True, "result": schemas.AnalysisOut.model_validate(a).model_dump(mode="json")})
        except (InvalidUrl, BlockedTarget) as exc:
            out.append({"ok": False, "url": item.url[:200], "error": str(exc)})
    return {"count": len(out), "items": out}


@router.get("/analyses/{analysis_id}", response_model=schemas.AnalysisOut, tags=["análisis"])
def get_analysis(analysis_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Analysis, analysis_id)
    if not a:
        raise HTTPException(404, "No encontrado")
    if a.user_id != user.id and not has_perm(user.role, "analysis:read_all"):
        raise HTTPException(403, "Permiso insuficiente")
    return a


# ---------------- alertas ----------------
def _alert_out(al: Alert, an: Analysis | None) -> dict:
    d = schemas.AlertOut.model_validate(al)
    d.url, d.domain, d.score = (an.url, an.domain, an.score) if an else (None, None, None)
    return d.model_dump(mode="json")


@router.get("/alerts", tags=["alertas"])
def list_alerts(status: str | None = None, level: str | None = None, limit: int = Query(50, le=200), offset: int = 0,
                user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    q = select(Alert, Analysis).join(Analysis, Analysis.id == Alert.analysis_id).order_by(Alert.created_at.desc())
    if status:
        q = q.where(Alert.status == status)
    if level:
        q = q.where(Alert.level == level)
    rows = db.execute(q.limit(limit).offset(offset)).all()
    return [_alert_out(al, an) for al, an in rows]


@router.get("/alerts/{alert_id}", tags=["alertas"])
def get_alert(alert_id: int, user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    al = db.get(Alert, alert_id)
    if not al:
        raise HTTPException(404, "No encontrada")
    an = db.get(Analysis, al.analysis_id)
    return {**_alert_out(al, an), "analysis": schemas.AnalysisOut.model_validate(an).model_dump(mode="json")}


@router.patch("/alerts/{alert_id}", tags=["alertas"])
def patch_alert(alert_id: int, body: schemas.AlertPatch, request: Request,
                user: User = Depends(require("alerts:write")), db: Session = Depends(get_db)):
    al = db.get(Alert, alert_id)
    if not al:
        raise HTTPException(404, "No encontrada")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(al, k, v)
    db.commit()
    audit(db, "alert_update", user.email, f"alert:{alert_id}", request=request, detail=str(body.model_dump(exclude_unset=True)))
    return _alert_out(al, db.get(Analysis, al.analysis_id))


# ---------------- dashboard / reportes ----------------
def _summary(db: Session) -> dict:
    total = db.scalar(select(func.count()).select_from(Analysis)) or 0
    by_level = {l: c for l, c in db.execute(select(Analysis.level, func.count()).group_by(Analysis.level)).all()}
    by_status = {s: c for s, c in db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all()}
    since = datetime.now(timezone.utc) - timedelta(days=7)
    recent = db.execute(select(Analysis.created_at, Analysis.latency_ms).where(Analysis.created_at >= since)).all()
    per_day: dict[str, int] = {}
    for i in range(6, -1, -1):
        per_day[(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")] = 0
    lat = sorted(r[1] for r in recent)
    for ts, _ in recent:
        k = ts.strftime("%Y-%m-%d")
        if k in per_day:
            per_day[k] += 1
    p95 = lat[int(0.95 * (len(lat) - 1))] if lat else 0
    return {"total": total, "by_level": by_level, "alerts_by_status": by_status,
            "open_alerts": by_status.get("open", 0) + by_status.get("investigating", 0),
            "per_day": per_day, "latency_avg_ms": round(sum(lat) / len(lat), 2) if lat else 0, "latency_p95_ms": p95,
            "model": {"version": ml.version(), "is_demo": bool(ml.metadata().get("warning"))},
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}


@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard(user: User = Depends(require("dashboard")), db: Session = Depends(get_db)):
    return _summary(db)


@router.get("/reports", tags=["reportes"])
def list_reports(user: User = Depends(require("reports"))):
    return {"formats": list(reports.BUILDERS), "download": "/api/v1/reports/download?format=xlsx|pdf|docx"}


@router.get("/reports/download", tags=["reportes"])
def download_report(request: Request, format: str = Query("pdf", pattern="^(pdf|xlsx|docx)$"),
                    user: User = Depends(require("reports")), db: Session = Depends(get_db)):
    data = _summary(db)
    rows = db.execute(select(Alert, Analysis).join(Analysis, Analysis.id == Alert.analysis_id)
                      .order_by(Alert.created_at.desc()).limit(200)).all()
    data["alerts"] = [{"created_at": al.created_at.isoformat(), "domain": an.domain, "level": al.level,
                       "score": an.score, "status": al.status} for al, an in rows]
    build, mime = reports.BUILDERS[format]
    audit(db, "report_download", user.email, format, request=request)
    return Response(build(data), media_type=mime,
                    headers={"Content-Disposition": f"attachment; filename=bankshield-reporte.{format}"})


# ---------------- auditoría / usuarios / inteligencia ----------------
@router.get("/audit/events", tags=["auditoría"])
def audit_events(limit: int = Query(100, le=500), user: User = Depends(require("audit:read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)).all()
    return [{"id": r.id, "ts": r.ts.isoformat(), "user": r.user_email, "action": r.action, "resource": r.resource,
             "outcome": r.outcome, "ip": r.ip, "detail": r.detail} for r in rows]


@router.get("/users", response_model=list[schemas.UserOut], tags=["usuarios"])
def list_users(user: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.post("/users", response_model=schemas.UserOut, status_code=201, tags=["usuarios"])
def create_user(body: schemas.UserCreate, request: Request, admin: User = Depends(require("users:manage")),
                db: Session = Depends(get_db)):
    if get_user_by_email(db, body.email):
        raise HTTPException(409, "El correo ya existe")
    u = User(email=body.email.lower(), full_name=body.full_name, role=body.role, password_hash=hash_password(body.password))
    db.add(u)
    db.commit()
    audit(db, "user_create", admin.email, u.email, request=request, detail=f"rol={u.role}")
    return u


@router.patch("/users/{user_id}/active", response_model=schemas.UserOut, tags=["usuarios"])
def set_active(user_id: int, active: bool, request: Request, admin: User = Depends(require("users:manage")),
               db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "No encontrado")
    if u.id == admin.id:
        raise HTTPException(400, "No puedes desactivar tu propia cuenta")
    u.is_active = active
    db.commit()
    audit(db, "user_active", admin.email, u.email, request=request, detail=str(active))
    return u


@router.post("/intel/indicators", status_code=201, tags=["inteligencia"])
def add_indicator(body: schemas.IndicatorIn, request: Request, user: User = Depends(require("intel:write")),
                  db: Session = Depends(get_db)):
    if not threat_intel.add_indicator(db, body.url, "manual", body.kind):
        raise HTTPException(409, "URL inválida o indicador ya existente")
    db.commit()
    audit(db, "indicator_add", user.email, body.url[:200], request=request)
    return {"status": "added"}


@router.post("/intel/refresh", tags=["inteligencia"])
def refresh_intel(request: Request, user: User = Depends(require("intel:write")), db: Session = Depends(get_db)):
    rep = threat_intel.refresh_feeds(db)
    audit(db, "intel_refresh", user.email, request=request, detail=str(rep)[:900])
    return rep


@router.get("/intel/status", tags=["inteligencia"])
def intel_status(user: User = Depends(require("intel:write")), db: Session = Depends(get_db)):
    rows = db.execute(select(ThreatIndicator.source, func.count(), func.max(ThreatIndicator.added_at)).group_by(ThreatIndicator.source)).all()
    return [{"source": s, "indicators": c, "last_update": m.isoformat() if m else None} for s, c, m in rows]


@router.get("/model", tags=["modelo"])
def model_info(user: User = Depends(require("dashboard"))):
    return ml.metadata()
