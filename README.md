# BankShield AI

Plataforma de detección y prevención de phishing en procesos bancarios: API FastAPI, motor de reglas + modelo ML +
inteligencia de amenazas, explicaciones por agente, alertas, auditoría, reportes (PDF/Word/Excel) y panel React.
Un solo contenedor sirve API y frontend; PostgreSQL para persistencia.

## Estado real del proyecto (léelo antes de usarlo)

| Componente | Estado |
|---|---|
| API REST `/api/v1` (analyze, batch, analyses, alerts, dashboard, reports, audit, users, intel, health/ready) | Implementado y probado (24 pruebas pytest, todas pasan) |
| Auth JWT + roles (admin, analyst, operator, auditor, manager) verificados en backend, bloqueo por intentos, rate limit | Implementado y probado |
| Protección SSRF: el análisis es **solo sintáctico**, no se conecta al destino; rechaza IP privadas/loopback/link-local y esquemas no http(s) | Implementado y probado |
| Motor de reglas + ML (scikit-learn: regresión logística, Random Forest, Gradient Boosting) | Implementado. **El modelo incluido se entrena con datos SINTÉTICOS de demostración**; sus métricas (1.0) no significan nada. Entrena con PhiUSIIL (ver abajo) |
| Inteligencia de amenazas | Indicadores en BD + importación de feeds de texto plano (`THREAT_FEED_URLS`). Sin feeds cargados la respuesta indica `data_incomplete` y no declara "seguro provisional" |
| Agente explicativo | Plantilla determinista; LLM opcional (`ANTHROPIC_API_KEY`) solo reformula, nunca decide el riesgo |
| Frontend React+TS (login, analizador, panel, alertas, auditoría) | Compila; probado el servido SPA + API de extremo a extremo con curl; **sin pruebas automáticas de UI** |
| Reportes PDF/Word/Excel | Implementado y probado (formato de archivo válido) |
| Workflows n8n (3) | JSON generados; **no ejecutados en n8n** |
| Docker / Render | Configuración incluida; **el build Docker y el despliegue en Render no se ejecutaron en este entorno** |
| Pendiente / no incluido | Alembic (se usa `create_all`), LangChain/LangFlow/LangGraph, Redis/Celery, WebSockets (el panel hace polling cada 5 s), Google Safe Browsing/VirusTotal, gestión de incidentes separada, pruebas de carga, DNS/WHOIS/TLS |

Decisión: monolito modular; sin LangChain/Redis/Celery porque el flujo mínimo no los requiere (añadir tras medir).

## Ejecutar con Docker
```bash
cp .env.example .env       # edita SECRET_KEY y ADMIN_PASSWORD
docker compose up --build  # http://localhost:8000  (docs API: /docs)
docker compose --profile n8n up -d n8n   # opcional, http://localhost:5678
```
Ingreso: `ADMIN_EMAIL` / `ADMIN_PASSWORD`. Con `SEED_DEMO=true` se crean cuentas `analyst|operator|auditor|manager@bankshield.local`
con clave `Demo#2026-Cambiar` y 2 indicadores de prueba (dominios `.test`). **Nunca uses SEED_DEMO en producción.**

## Ejecutar sin Docker
```bash
./scripts/run_local.sh                      # API en :8000 (SQLite)
cd frontend && npm install && npm run dev   # UI en :5173 con proxy a la API
cd backend && pip install -r requirements-dev.txt && pytest
```

## Desplegar en Render
1. Sube el repositorio a GitHub.
2. En Render: **New → Blueprint**, selecciona el repo (usa `render.yaml`: servicio web Docker + PostgreSQL).
3. Render genera `SECRET_KEY` y `ADMIN_PASSWORD`; cópiala desde *Environment*. Usuario: `admin@bankshield.local`.
4. Opcional: `THREAT_FEED_URLS`, `N8N_WEBHOOK_URL`, `N8N_WEBHOOK_SECRET`.
El plan *free* duerme el servicio por inactividad y la BD gratuita expira; usa plan de pago para uso real.

## Entrenar con datos reales
Descarga PhiUSIIL desde UCI (revisa licencia) y ejecuta:
```bash
cd backend && python -m app.ml.train --csv PhiUSIIL_Phishing_URL_Dataset.csv --url-col URL --label-col label --legit-label 1
```
**Verifica en la ficha del dataset qué valor significa "legítima"** antes de usar `--legit-label`. Split train/val/test por dominio.
Solo se usan características derivables de la URL. Resultados en `backend/app/ml/artifacts/metrics.json`.

## Feeds de amenazas
`THREAT_FEED_URLS=https://…/feed.txt` (una URL por línea). Respeta términos de uso y cuotas de cada proveedor
(OpenPhish, PhishTank, URLhaus). `POST /api/v1/intel/refresh` (o el workflow n8n 02) los importa. Que una URL no figure no prueba seguridad.

## Seguridad (resumen)
PBKDF2-SHA256; JWT con expiración; permisos por rol en backend; auditoría de login/alertas/reportes/usuarios; no se persisten query ni
fragmento de las URL; cabeceras de seguridad y CSP; mensajes de login genéricos; límites en memoria (usa Redis si escalas a varias instancias).
El token se guarda en `localStorage` (riesgo XSS asumido; considera cookies HttpOnly).

Más detalle en `docs/arquitectura.md`. Licencia MIT.
