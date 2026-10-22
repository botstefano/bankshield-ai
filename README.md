# BankShield AI

Plataforma inteligente de detección y mitigación de phishing en procesos y operaciones bancarias.
Reescrita como una aplicación React moderna con TypeScript y Vite, preservando íntegramente la lógica de negocio, motor de reglas heurísticas, scoring probabilístico ML, base local de indicadores de inteligencia de amenazas (IoC), centro de alertas, registro de auditoría inmutable, exportación de reportes de cumplimiento y control de acceso basado en roles (RBAC).

## Características y Capacidades

| Componente | Descripción |
|---|---|
| **Motor de Análisis Sintáctico** | Evaluación heurística determinista (16 reglas de ciberseguridad) + modelo probabilístico ML. Protección SSRF: el análisis es puramente sintáctico, sin conectarse al destino; rechaza IPs privadas, bucles locales y esquemas no permitidos. |
| **Inteligencia de Amenazas (IoC)** | Base desacoplada de indicadores maliciosos. Consulta local instantánea (coincidencia exacta o coincidencia por host). Mantiene advertencia de contingencia (`data_incomplete`) si no hay feeds externos activos. |
| **Control de Acceso (RBAC)** | Roles preconfigurados con permisos granulares: `admin` (total), `analyst` (análisis, gestión de alertas, inteligencia), `operator` (análisis de URLs), `auditor` (lectura de auditoría y reportes), `manager` (panel y reportes). Selector rápido por rol para demostración. |
| **Centro de Alertas de Seguridad** | Generación automática ante niveles de riesgo **Alto** o **Crítico**. Filtrado por estado (`open`, `investigating`, `confirmed`, `false_positive`, `resolved`), actualización en línea y vista detallada del análisis. |
| **Panel de Seguridad y Métricas** | Indicadores KPI (URLs analizadas, alertas pendientes, latencia media y percentil p95), gráfico de barras por nivel de riesgo y gráfico de columnas con volumen de los últimos 7 días. |
| **Exportación de Reportes** | Generación y descarga directa en tres formatos estándar para auditoría regulatoria: PDF (imprimible/ejecutivo), Excel (.csv/.xlsx con UTF-8 BOM) y Word (.docx/.doc). |
| **Registro de Auditoría** | Trazabilidad inmutable de todas las acciones operativas (`login`, `analyze`, `alert_update`, `user_create`, `report_download`, etc.) con registro de usuario, IP, resultado y detalle técnico. |
| **Gestión de Amenazas y Usuarios** | Administración de indicadores manuales y feeds externos; gestión de usuarios y estados activos para cuentas del sistema. |

## Roles y Cuentas de Prueba

Para facilitar la evaluación y demostración, se incluyen cuentas preconfiguradas seleccionables con 1 clic en la pantalla de inicio de sesión:

- **Administrador**: `admin@bankshield.local` (Acceso completo a todos los módulos)
- **Analista SOC L2**: `analyst@bankshield.local` (Análisis, alertas, reportes, inteligencia)
- **Operador de Mesa**: `operator@bankshield.local` (Análisis individual y por lotes)
- **Auditor Interno**: `auditor@bankshield.local` (Panel, alertas, auditoría, reportes)
- **Gerente de Riesgo**: `manager@bankshield.local` (Panel y reportes ejecutivos)

## Ejemplos Rápidos de Prueba

En la pestaña **Analizar URL**, puedes probar directamente con un solo clic:
1. `https://www.viabcp.com/canales/banca-por-internet` — Dominio bancario autorizado (Riesgo Seguro Provisional, puntaje 0).
2. `https://bcp-seguro-acceso.example-phish.test/login` — Dominio suplantador / lookalike listado en feeds de amenazas (Riesgo Crítico, puntaje >95).
3. `http://banca@185.220.101.5:8080/interbank/login` — Host por dirección IP con credenciales embebidas `@` y puerto no estándar (Riesgo Alto).
4. `https://bbva-portal-cliente.xyz/login` — TLD sospechoso `.xyz` con abuso de marca bancaria y palabras de autenticación (Riesgo Alto/Crítico).
5. `https://bit.ly/3xSecurityVerify` — Servicio de acortamiento de URL con destino encubierto (Riesgo Medio).

## Ejecución Local

```bash
npm install
npm run dev
```

El servidor de desarrollo escuchará en `http://localhost:3000`.

Para compilar la aplicación para producción:
```bash
npm run build
```

## Despliegue en Render

La aplicación está lista para desplegarse en **Render** como un **Static Site** (100% gratuito, con CDN global, SSL automático y soporte SPA):

### Opción 1: Con Render Blueprint (Recomendado y Automático)
1. Conecta tu repositorio de GitHub o GitLab a [Render](https://dashboard.render.com).
2. Haz clic en **New +** y selecciona **Blueprint**.
3. Selecciona tu repositorio. Render detectará automáticamente el archivo `render.yaml` incluido en el proyecto.
4. Haz clic en **Apply**. Render compilará (`npm install && npm run build`) y publicará la carpeta `dist` con las reglas de reescritura SPA y cabeceras de seguridad.

### Opción 2: Manual desde el Dashboard de Render
1. En [Render Dashboard](https://dashboard.render.com), haz clic en **New +** → **Static Site**.
2. Conecta tu repositorio.
3. Configura los parámetros:
   - **Name**: `bankshield-ai`
   - **Branch**: `main` (o tu rama activa)
   - **Build Command**: `npm install && npm run build`
   - **Publish Directory**: `dist`
4. En **Redirects/Rewrites**, agrega una regla de reescritura para Single Page Application:
   - **Type**: `Rewrite`
   - **Source**: `/*`
   - **Destination**: `/index.html`
5. Haz clic en **Create Static Site**. ¡Tu aplicación estará en línea en pocos segundos!

## Licencia

MIT License.

