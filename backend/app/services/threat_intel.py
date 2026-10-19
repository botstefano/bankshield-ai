"""Capa de inteligencia de amenazas desacoplada.

Las fuentes (feeds públicos, indicadores manuales, demo) se cargan en la tabla
`threat_indicators` y la consulta se hace localmente (rápida y sin enviar la URL a terceros).
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import ThreatIndicator
from .url_features import InvalidUrl, BlockedTarget, normalize_url


def _norm(url: str) -> tuple[str, str] | None:
    try:
        p = normalize_url(url)
        return p["normalized"], p["host"]
    except (InvalidUrl, BlockedTarget):
        return None


def add_indicator(db: Session, url: str, source: str, kind: str = "phishing") -> bool:
    n = _norm(url)
    if not n:
        return False
    exists = db.scalar(select(ThreatIndicator.id).where(ThreatIndicator.url_norm == n[0], ThreatIndicator.source == source))
    if exists:
        return False
    db.add(ThreatIndicator(url_norm=n[0], host=n[1], source=source, kind=kind))
    return True


def lookup(db: Session, url_norm: str, host: str) -> dict:
    """Devuelve hits y estado de las fuentes."""
    rows = db.scalars(select(ThreatIndicator).where(ThreatIndicator.host == host)).all()
    exact = [r for r in rows if r.url_norm == url_norm]
    host_only = [r for r in rows if r.url_norm != url_norm]
    stats = db.execute(
        select(ThreatIndicator.source, func.count(), func.max(ThreatIndicator.added_at)).group_by(ThreatIndicator.source)
    ).all()
    sources = {s: {"count": c, "last_update": _aware(m)} for s, c, m in stats}
    real = {s: v for s, v in sources.items() if s not in ("demo", "manual")}
    limit = datetime.now(timezone.utc) - timedelta(hours=settings.feed_stale_hours)
    fresh_real = [s for s, v in real.items() if v["last_update"] and v["last_update"] >= limit]
    return {"exact": exact, "host": host_only, "sources": sources,
            "incomplete": len(fresh_real) == 0}


def _aware(d):
    if d is not None and d.tzinfo is None:
        return d.replace(tzinfo=timezone.utc)
    return d


def refresh_feeds(db: Session) -> dict:
    """Descarga feeds de texto plano (una URL por línea) definidos en THREAT_FEED_URLS.

    Las URL de los feeds provienen de la configuración del administrador (no del usuario final),
    se limita el tamaño de descarga y el tiempo de espera.
    """
    report = {}
    for feed in settings.feed_urls:
        name = urlsplit(feed).hostname or feed
        try:
            added, total = 0, 0
            with httpx.stream("GET", feed, timeout=20, follow_redirects=False) as r:
                r.raise_for_status()
                size, buf = 0, []
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > settings.feed_max_bytes:
                        raise ValueError("feed excede el tamaño máximo")
                    buf.append(chunk)
            for line in b"".join(buf).decode("utf-8", "ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                total += 1
                added += add_indicator(db, line, name)
            db.commit()
            report[name] = {"status": "ok", "lines": total, "added": added}
        except Exception as exc:  # una fuente caída no debe afectar a las demás
            db.rollback()
            report[name] = {"status": "error", "detail": str(exc)[:200]}
    if not settings.feed_urls:
        report["info"] = "THREAT_FEED_URLS no configurado: no hay feeds externos."
    return report
