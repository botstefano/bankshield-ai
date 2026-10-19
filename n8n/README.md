# Workflows de n8n

Importa cada JSON desde **n8n → Workflows → Import from file**.

| Archivo | Función |
|---|---|
| `01-alerta-alto-riesgo.json` | Recibe el webhook que BankShield envía al crear una alerta alta/crítica, valida el secreto y notifica. |
| `02-refresco-inteligencia.json` | Cada 6 h inicia sesión y llama a `POST /api/v1/intel/refresh`. |
| `03-supervision-servicio.json` | Cada 5 min consulta `/api/v1/ready` (3 reintentos) y avisa si falla. |

## Variables de entorno de n8n
`BANKSHIELD_URL`, `BANKSHIELD_EMAIL`, `BANKSHIELD_PASSWORD` (usa un usuario *analyst* dedicado), `N8N_WEBHOOK_SECRET`
(mismo valor que en BankShield), `NOTIFY_WEBHOOK_URL` (p. ej. Slack/Teams incoming webhook).

En BankShield define `N8N_WEBHOOK_URL=https://<tu-n8n>/webhook/bankshield-alert` y `N8N_WEBHOOK_SECRET`.
No hay credenciales reales en los archivos. **Estado:** JSON generados y con estructura revisada; *no se ejecutaron en una instancia de n8n* (pendiente de validar).
