"""Normalización de URL y extracción de características (solo análisis sintáctico).

Este módulo NUNCA se conecta al destino: no hay resolución DNS ni descargas,
lo que elimina el riesgo de SSRF en el análisis. Las URL a hosts internos se rechazan.
"""
import ipaddress
import math
import re
from urllib.parse import urlsplit

from ..config import settings

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work", "support",
                   "country", "kim", "loan", "icu", "buzz", "rest", "cyou", "cam", "monster"}
KEYWORDS = ("login", "signin", "verify", "verif", "secure", "account", "update", "confirm", "banking",
            "password", "token", "clave", "validar", "actualiza", "suspend", "bloque", "acceso", "seguro")
SECOND_LEVEL = {"com", "org", "net", "gob", "edu", "co", "gov", "ac"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})

FEATURE_ORDER = [
    "url_length", "host_length", "num_dots", "num_subdomains", "num_hyphens_host", "digit_ratio_host",
    "has_ip", "has_at", "is_https", "is_shortener", "suspicious_tld", "is_idn", "num_keywords",
    "path_depth", "num_params", "host_entropy", "brand_abuse", "min_brand_distance", "nonstandard_port",
]


class InvalidUrl(ValueError):
    pass


class BlockedTarget(ValueError):
    pass


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return host == "localhost" or host.endswith((".local", ".internal", ".localhost", ".lan"))


def normalize_url(raw: str) -> dict:
    """Devuelve partes normalizadas. Lanza InvalidUrl / BlockedTarget."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or any(c in raw for c in "\r\n\t "):
        raise InvalidUrl("URL vacía, demasiado larga o con espacios/saltos de línea.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise InvalidUrl(f"URL mal formada: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise InvalidUrl(f"Esquema no permitido: '{parts.scheme}'. Solo http/https.")
    if not host:
        raise InvalidUrl("La URL no contiene un host.")
    if _is_private(host):
        raise BlockedTarget("Destino interno/privado no permitido (protección SSRF).")
    is_idn = False
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        is_idn = True
        host = host.encode("idna").decode("ascii")
    if host.startswith("xn--") or ".xn--" in host:
        is_idn = True
    path = parts.path or "/"
    # se descarta query y fragmento para no persistir parámetros sensibles
    normalized = f"{parts.scheme}://{host}{':' + str(port) if port else ''}{path}"
    return {
        "scheme": parts.scheme, "host": host, "port": port, "path": path,
        "query": parts.query, "has_userinfo": "@" in (parts.netloc or ""),
        "normalized": normalized, "is_idn": is_idn, "raw_len": len(raw),
        "full_lower": raw.lower(),
    }


def brand_tokens() -> dict[str, str]:
    """token de marca -> dominio legítimo registrable"""
    return {d.split(".")[0]: d for d in settings.bank_domains}


def is_authorized_domain(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in settings.bank_domains)


def extract_features(p: dict) -> dict:
    host = p["host"]
    reg = registrable_domain(host)
    reg_label = reg.split(".")[0]
    labels = host.split(".")
    num_sub = max(0, len(labels) - (len(reg.split("."))))
    has_ip = _is_ip(host)
    tld = labels[-1]
    brands = brand_tokens()
    authorized = is_authorized_domain(host)
    leet_label = reg_label.translate(LEET)
    min_dist = 10
    lookalike_of = None
    for token, dom in brands.items():
        if reg == dom:
            continue
        for cand in {reg_label, leet_label}:
            d = _levenshtein(cand, token)
            if d < min_dist:
                min_dist = d
                if d <= (1 if len(token) <= 4 else 2) and len(token) >= 3:
                    lookalike_of = dom
    brand_in_host = [t for t in brands if t in host.replace("-", "") and not authorized]
    keywords = sum(1 for k in KEYWORDS if k in p["full_lower"])
    return {
        "url_length": len(p["normalized"]), "host_length": len(host), "num_dots": host.count("."),
        "num_subdomains": num_sub, "num_hyphens_host": host.count("-"),
        "digit_ratio_host": sum(c.isdigit() for c in host) / max(1, len(host)),
        "has_ip": int(has_ip), "has_at": int(p["has_userinfo"]), "is_https": int(p["scheme"] == "https"),
        "is_shortener": int(reg in SHORTENERS), "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_idn": int(p["is_idn"]), "num_keywords": keywords,
        "path_depth": len([s for s in p["path"].split("/") if s]),
        "num_params": len([q for q in p["query"].split("&") if q]),
        "host_entropy": round(_entropy(host), 3), "brand_abuse": int(bool(brand_in_host)),
        "min_brand_distance": 10 if authorized else min_dist,
        "nonstandard_port": int(p["port"] not in (None, 80, 443)),
        # auxiliares (no entran al ML)
        "_registrable": reg, "_authorized": authorized, "_lookalike_of": lookalike_of,
        "_brand_in_host": brand_in_host,
    }


def feature_vector(f: dict) -> list[float]:
    return [float(f[k]) for k in FEATURE_ORDER]


def features_from_url(raw: str) -> dict:
    return extract_features(normalize_url(raw))
