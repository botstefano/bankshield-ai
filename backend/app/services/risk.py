"""Motor de riesgo: reglas deterministas + ML + inteligencia de amenazas.

La decisión NO depende de un LLM. Los umbrales son configurables (RISK_THRESHOLDS).
"""
import time

from sqlalchemy.orm import Session

from ..config import settings
from ..ml import model as ml
from . import threat_intel
from .url_features import extract_features, normalize_url

ENGINE_VERSION = "1.0.0"

LEVELS = ["seguro_provisional", "bajo", "medio", "alto", "critico", "desconocido"]

RECOMMENDATIONS = {
    "seguro_provisional": "No se detectaron indicadores relevantes. Permitir según la política; esto no garantiza seguridad absoluta.",
    "bajo": "Indicios menores. Registrar y permitir según la política aplicable; mantener precaución.",
    "medio": "Indicadores sospechosos. Mostrar advertencia al usuario y solicitar revisión adicional antes de ingresar datos.",
    "alto": "Evidencia relevante de phishing. Bloquear o exigir confirmación reforzada y escalar a un analista.",
    "critico": "Evidencia sólida de amenaza grave (o coincidencia confirmada en fuentes). Bloquear mediante controles autorizados, abrir incidente y notificar.",
    "desconocido": "No se pudo completar el análisis. Aplicar la política de contingencia; NO asumir que la URL es segura.",
}


def level_for(score: float) -> str:
    lo, med, hi, crit = settings.thresholds
    if score >= crit:
        return "critico"
    if score >= hi:
        return "alto"
    if score >= med:
        return "medio"
    if score >= lo:
        return "bajo"
    return "seguro_provisional"


def _rules(f: dict, p: dict) -> list[tuple[int, str, str]]:
    r: list[tuple[int, str, str]] = []
    if f["has_ip"]:
        r.append((40, "ip_host", "El host es una dirección IP en lugar de un dominio."))
    if f["has_at"]:
        r.append((25, "userinfo_at", "La URL contiene '@' (credenciales embebidas), técnica de engaño habitual."))
    if f["is_idn"]:
        r.append((25, "idn_punycode", "El dominio usa caracteres Unicode/punycode (posible homógrafo)."))
    if f["is_shortener"]:
        r.append((15, "shortener", "Servicio de acortamiento de URL: el destino real está oculto."))
    if f["suspicious_tld"]:
        r.append((15, "suspicious_tld", "TLD frecuentemente asociado a abuso."))
    if f["_lookalike_of"]:
        r.append((45, "lookalike_domain", f"Dominio muy similar al dominio bancario legítimo {f['_lookalike_of']}."))
    if f["brand_abuse"]:
        r.append((35, "brand_abuse", f"Usa el nombre de una entidad ({', '.join(f['_brand_in_host'])}) en un dominio no autorizado."))
    if f["num_subdomains"] >= 4:
        r.append((15, "many_subdomains", f"Cantidad elevada de subdominios ({f['num_subdomains']})."))
    elif f["num_subdomains"] == 3:
        r.append((8, "some_subdomains", "Varios subdominios (3)."))
    if f["url_length"] > 120:
        r.append((15, "very_long_url", f"URL muy larga ({f['url_length']} caracteres)."))
    elif f["url_length"] > 75:
        r.append((8, "long_url", f"URL larga ({f['url_length']} caracteres)."))
    if f["num_hyphens_host"] >= 3:
        r.append((10, "hyphens", "Muchos guiones en el dominio."))
    if f["num_keywords"] >= 2:
        r.append((10, "keywords", f"Palabras típicas de suplantación ({f['num_keywords']} coincidencias)."))
    if not f["is_https"]:
        r.append((10, "no_https", "La conexión no usa HTTPS (y HTTPS por sí solo no prueba legitimidad)."))
    if f["nonstandard_port"]:
        r.append((8, "odd_port", "Puerto no estándar."))
    if f["digit_ratio_host"] > 0.3 and not f["has_ip"]:
        r.append((8, "digits", "Proporción alta de dígitos en el dominio."))
    return r


def assess(db: Session, raw_url: str) -> dict:
    """Evalúa una URL. Lanza InvalidUrl/BlockedTarget (el llamador responde 422)."""
    t0 = time.perf_counter()
    p = normalize_url(raw_url)
    f = extract_features(p)
    rules = _rules(f, p)
    rule_score = min(100, sum(x[0] for x in rules))
    ml_p = ml.predict_proba(f)
    intel = threat_intel.lookup(db, p["normalized"], p["host"])

    indicators = [{"code": c, "points": pts, "description": d} for pts, c, d in rules]
    evidence: list[dict] = []
    authorized = f["_authorized"]

    if authorized:
        score = min(5.0, rule_score * 0.1)
        evidence.append({"source": "reglas", "type": "authorized_domain", "detail": f"Dominio autorizado: {f['_registrable']}"})
    else:
        score = rule_score if ml_p is None else 0.55 * rule_score + 0.45 * ml_p * 100

    confirmed = bool(intel["exact"])
    for r in intel["exact"]:
        evidence.append({"source": r.source, "type": "confirmed_match", "detail": "La URL exacta figura en la fuente de amenazas.",
                         "listed_at": r.added_at.isoformat()})
    if intel["host"] and not confirmed:
        score = max(score, 70.0)
        indicators.append({"code": "host_listed", "points": 0, "description": "El dominio aparece en una fuente de amenazas con otra ruta."})
        for r in intel["host"][:3]:
            evidence.append({"source": r.source, "type": "host_match", "detail": f"Dominio listado con otra ruta: {r.url_norm}"})
    if confirmed:
        score = max(score, 95.0)
    if ml_p is not None:
        evidence.append({"source": "modelo_ml", "type": "model_score", "detail": f"Probabilidad bruta del modelo: {ml_p:.3f} (no calibrada)",
                         "model_version": ml.version()})
    evidence.append({"source": "reglas", "type": "rule_score", "detail": f"Puntaje de reglas: {rule_score}/100"})

    level = level_for(score)
    incomplete = intel["incomplete"]
    if incomplete:
        evidence.append({"source": "inteligencia", "type": "limitation",
                         "detail": "No hay feeds externos actualizados cargados: la ausencia de coincidencias no demuestra que la URL sea segura."})
        if level == "seguro_provisional" and not authorized:
            level = "bajo"  # política conservadora: sin inteligencia fresca no se declara 'seguro'
    if ml_p is None:
        evidence.append({"source": "modelo_ml", "type": "limitation", "detail": "Modelo ML no disponible; solo reglas e inteligencia."})

    return {
        "url": p["normalized"], "domain": p["host"], "level": level, "score": round(score, 1),
        "ml_probability": None if ml_p is None else round(ml_p, 4),
        "indicators": indicators, "evidence": evidence, "recommendation": RECOMMENDATIONS[level],
        "data_incomplete": incomplete, "engine_version": ENGINE_VERSION, "model_version": ml.version(),
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
