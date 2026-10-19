"""Agente explicativo.

Traduce las evidencias registradas a lenguaje claro. No decide el nivel de riesgo.
Por defecto es determinista (plantilla). Si ANTHROPIC_API_KEY está configurada, reformula el
mismo contenido con un LLM; ante cualquier fallo vuelve a la plantilla.
"""
import httpx

from ..config import settings

LEVEL_ES = {"seguro_provisional": "Seguro provisional", "bajo": "Bajo", "medio": "Medio",
            "alto": "Alto", "critico": "Crítico", "desconocido": "Desconocido"}


def _template(r: dict) -> str:
    lines = [f"Riesgo {LEVEL_ES[r['level']]} (puntaje {r['score']}/100) para el dominio {r['domain']}."]
    if r["indicators"]:
        lines.append("Se detectó: " + "; ".join(i["description"] for i in r["indicators"][:6]))
    confirmed = [e for e in r["evidence"] if e["type"] == "confirmed_match"]
    if confirmed:
        lines.append("Está listada en fuentes de amenazas: " + ", ".join(sorted({e["source"] for e in confirmed})) + ".")
    if r["data_incomplete"]:
        lines.append("Atención: la evaluación se hizo con datos de inteligencia incompletos o desactualizados.")
    lines.append(r["recommendation"])
    return " ".join(lines)


def explain(result: dict) -> str:
    base = _template(result)
    if not settings.anthropic_api_key:
        return base
    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": settings.anthropic_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": settings.llm_model, "max_tokens": 400,
                  "system": "Eres un analista de ciberseguridad bancaria. Reescribe en español claro (máx. 4 frases) SOLO los hechos dados. No inventes indicadores ni cambies el nivel de riesgo.",
                  "messages": [{"role": "user", "content": base}]},
            timeout=8,
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"].strip()
        return text or base
    except Exception:
        return base
