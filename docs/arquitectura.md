# Arquitectura

```
Navegador (React) ──► FastAPI (/api/v1) ──► PostgreSQL
                         ├─ url_features  (normalización, anti-SSRF, características)
                         ├─ risk          (reglas + ML + inteligencia → nivel)
                         ├─ threat_intel  (indicadores/feeds en BD)
                         ├─ agents/explainer (explicación basada en evidencias)
                         ├─ reports       (PDF/DOCX/XLSX)
                         └─► webhook ─► n8n (notificación / supervisión)
```
**Decisión clave:** la decisión de riesgo es determinista (reglas + ML + coincidencias); el LLM nunca decide.

**Niveles:** `RISK_THRESHOLDS` (bajo, medio, alto, crítico; por defecto 15/35/60/80). Coincidencia exacta en una fuente ⇒ puntaje ≥ 95.
Dominios autorizados (`BANK_DOMAINS`) ⇒ puntaje ≤ 5. Sin feeds externos actualizados ⇒ nunca "seguro provisional" para dominios no autorizados.
El puntaje no es una probabilidad calibrada.

**Roles:** admin (todo); analyst (analizar, alertas, panel, reportes, inteligencia); operator (analizar; solo ve sus análisis);
auditor (auditoría, reportes, panel, alertas lectura); manager (panel, reportes, alertas lectura).

**Datos:** users, analyses, alerts, audit_logs, threat_indicators (SQLAlchemy; tablas creadas al iniciar).

**Desviaciones respecto al prompt original:** reportes vía `GET /reports/download`; sin Alembic, LangChain/LangFlow, Redis/Celery, WebSockets
ni módulo de incidentes separado (las alertas cubren el seguimiento básico). Son los siguientes pasos naturales.
