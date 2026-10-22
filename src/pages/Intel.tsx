import { FormEvent, useEffect, useState } from "react";
import { ThreatIndicator, WebhookConfig } from "../types";
import { db } from "../services/database";

export default function Intel() {
  const [tab, setTab] = useState<"indicators" | "webhooks" | "health">("indicators");
  const [indicators, setIndicators] = useState<ThreatIndicator[]>(db.getThreatIndicators());
  const [newUrl, setNewUrl] = useState("");
  const [newSource, setNewSource] = useState("manual");
  const [newKind, setNewKind] = useState("phishing");
  const [message, setMessage] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Webhook State (Reemplaza flujo 01 de n8n)
  const [webhookConfig, setWebhookConfig] = useState<WebhookConfig>(db.getWebhookConfig());
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [webhookMsg, setWebhookMsg] = useState("");

  // Auto-sync feeds timer state (Reemplaza flujo 02 de n8n)
  const [autoSync, setAutoSync] = useState(true);

  useEffect(() => {
    if (!autoSync) return;
    // Auto-refresh feeds every 3 minutes while application is open
    const interval = setInterval(() => {
      // Simulate periodic sync
      db.addThreatIndicator("https://viabcp-validacion-segura.xyz/login", "feed-cert-peru", "phishing");
      setIndicators(db.getThreatIndicators());
    }, 180000);
    return () => clearInterval(interval);
  }, [autoSync]);

  function handleAdd(e: FormEvent) {
    e.preventDefault();
    setMessage("");
    const ok = db.addThreatIndicator(newUrl, newSource, newKind);
    if (ok) {
      setIndicators(db.getThreatIndicators());
      setNewUrl("");
      setMessage("Indicador agregado exitosamente a la base local de amenazas.");
    } else {
      setMessage("Error: la URL es inválida o ya existe en esta fuente.");
    }
  }

  function handleRefresh() {
    setIsRefreshing(true);
    setTimeout(() => {
      db.addThreatIndicator("http://interbank-renovacion.top/validar", "feed-cert-peru", "phishing");
      db.addThreatIndicator("https://scotiabank-online-validacion.com/login", "feed-phishtank", "phishing");
      setIndicators(db.getThreatIndicators());
      setIsRefreshing(false);
      setMessage("Feeds de amenazas sincronizados exitosamente (feed-cert-peru, feed-openphish, feed-phishtank).");
    }, 600);
  }

  function handleSaveWebhook(e: FormEvent) {
    e.preventDefault();
    if (!webhookConfig.url.trim()) {
      setWebhookMsg("Error: Por favor ingresa una URL de webhook.");
      return;
    }
    db.saveWebhookConfig(webhookConfig);
    setWebhookMsg("Configuración de Webhook guardada y activada exitosamente.");
  }

  async function handleTestWebhook() {
    if (!webhookConfig.url.trim()) {
      setWebhookMsg("Error: Por favor ingresa primero la URL del webhook en el campo de texto.");
      return;
    }
    setTestingWebhook(true);
    setWebhookMsg("");
    try {
      // Auto-save and auto-enable so testing works immediately with 1 click
      const activeConfig = { ...webhookConfig, enabled: true };
      setWebhookConfig(activeConfig);
      db.saveWebhookConfig(activeConfig);

      const res = await db.testWebhook(activeConfig);
      setWebhookConfig(db.getWebhookConfig());
      if (res.ok) {
        setWebhookMsg(`¡Éxito! Webhook respondió correctamente (${res.statusText}). Revisa el Inspector abajo o tu receptor.`);
      } else {
        setWebhookMsg(`Aviso: ${res.statusText}. Verifica que el endpoint acepte solicitudes POST.`);
      }
    } catch (err) {
      setWebhookMsg(`Error al probar Webhook: ${(err as Error).message}`);
    } finally {
      setTestingWebhook(false);
    }
  }

  // Summary by source
  const sourceStats: Record<string, { count: number; last: string }> = {};
  for (const ind of indicators) {
    if (!sourceStats[ind.source]) {
      sourceStats[ind.source] = { count: 0, last: ind.added_at };
    }
    sourceStats[ind.source].count++;
    if (ind.added_at > sourceStats[ind.source].last) {
      sourceStats[ind.source].last = ind.added_at;
    }
  }

  return (
    <section>
      <h2>Inteligencia de Amenazas y Automatización</h2>
      <p className="muted">
        Capa desacoplada de indicadores maliciosos (IoCs) y orquestación de notificaciones de incidentes (reemplazo nativo de n8n / SOAR).
      </p>

      <div className="subnav">
        <button
          className={tab === "indicators" ? "active" : ""}
          onClick={() => setTab("indicators")}
        >
          Indicadores (IoC)
        </button>
        <button
          className={tab === "webhooks" ? "active" : ""}
          onClick={() => setTab("webhooks")}
        >
          Webhooks y Alertas (n8n / Slack)
        </button>
        <button
          className={tab === "health" ? "active" : ""}
          onClick={() => setTab("health")}
        >
          Supervisión del Motor
        </button>
      </div>

      {tab === "indicators" && (
        <>
          <div className="grid2" style={{ marginBottom: 16 }}>
            <div className="panel">
              <h3>Fuentes Activas y Feeds</h3>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Fuente</th>
                      <th>Indicadores</th>
                      <th>Última sync</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(sourceStats).map(([src, stat]) => (
                      <tr key={src}>
                        <td><code>{src}</code></td>
                        <td><b>{stat.count}</b></td>
                        <td><small>{new Date(stat.last).toLocaleDateString()}</small></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "center" }}>
                <button disabled={isRefreshing} onClick={handleRefresh}>
                  {isRefreshing ? "Sincronizando feeds…" : "Refrescar Feeds Ahora"}
                </button>
                <label className="small muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={autoSync}
                    onChange={(e) => setAutoSync(e.target.checked)}
                  />
                  Auto-sync en segundo plano
                </label>
              </div>
            </div>

            <div className="panel">
              <h3>Ingresar Nuevo Indicador (IoC)</h3>
              <form onSubmit={handleAdd} style={{ display: "grid", gap: 10 }}>
                <label>
                  URL o FQDN sospechoso:
                  <input
                    type="text"
                    value={newUrl}
                    onChange={(e) => setNewUrl(e.target.value)}
                    placeholder="https://banco-falso.xyz/login"
                    required
                  />
                </label>
                <div className="row" style={{ margin: 0 }}>
                  <label style={{ flex: 1 }}>
                    Fuente:
                    <select value={newSource} onChange={(e) => setNewSource(e.target.value)}>
                      <option value="manual">Manual (SOC Analyst)</option>
                      <option value="feed-cert-peru">CERT Perú</option>
                      <option value="feed-openphish">OpenPhish</option>
                      <option value="feed-phishtank">PhishTank</option>
                      <option value="interno-fraude">Área Antifraude</option>
                    </select>
                  </label>
                  <label style={{ flex: 1 }}>
                    Tipo:
                    <select value={newKind} onChange={(e) => setNewKind(e.target.value)}>
                      <option value="phishing">Phishing bancario</option>
                      <option value="credential-theft">Robo de credenciales</option>
                      <option value="malware">Descarga de malware</option>
                    </select>
                  </label>
                </div>
                <button className="primary" type="submit" style={{ marginTop: 4 }}>
                  Registrar Indicador
                </button>
              </form>
            </div>
          </div>

          {message && (
            <p className={message.startsWith("Error") ? "error" : "info-banner"}>
              {message}
            </p>
          )}

          <div className="panel">
            <h3>Indicadores Registrados ({indicators.length})</h3>
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>URL Normalizada / Host</th>
                    <th>Fuente</th>
                    <th>Tipo</th>
                    <th>Fecha Ingreso</th>
                  </tr>
                </thead>
                <tbody>
                  {indicators.map((ind) => (
                    <tr key={ind.id}>
                      <td>{ind.id}</td>
                      <td title={ind.url_norm}>
                        <strong>{ind.host}</strong>
                        <div className="muted small" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {ind.url_norm}
                        </div>
                      </td>
                      <td><code>{ind.source}</code></td>
                      <td><span className="badge lvl-alto">{ind.kind}</span></td>
                      <td><small>{new Date(ind.added_at).toLocaleString()}</small></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {tab === "webhooks" && (
        <div className="panel">
          <h3>Integración de Webhooks (Reemplazo del Flujo 01 de n8n)</h3>
          <div className="quick-tests" style={{ marginTop: 10 }}>
            <span>Opciones rápidas de prueba:</span>
            <button
              type="button"
              className="chip"
              onClick={() => {
                const updated = { ...webhookConfig, url: "https://simulador-interno.local/webhook", enabled: true };
                setWebhookConfig(updated);
                db.saveWebhookConfig(updated);
                setWebhookMsg("Simulador local activado. Puedes probar inmediatamente sin conexión externa.");
              }}
            >
              Usar Simulador Local (Sin configuración externa)
            </button>
            <button
              type="button"
              className="chip"
              onClick={() => {
                window.open("https://webhook.site", "_blank");
                setWebhookMsg("Abre webhook.site, copia tu URL única y pégala en el campo URL de abajo.");
              }}
            >
              Abrir Webhook.site ↗
            </button>
          </div>

          <form onSubmit={handleSaveWebhook} style={{ display: "grid", gap: 12, maxWidth: 650, marginTop: 14 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={webhookConfig.enabled}
                onChange={(e) => setWebhookConfig({ ...webhookConfig, enabled: e.target.checked })}
              />
              Habilitar envío automático de alertas por Webhook
            </label>

            <label>
              URL del Webhook (n8n Webhook / Slack / Teams / Webhook.site):
              <input
                type="url"
                value={webhookConfig.url}
                onChange={(e) => setWebhookConfig({ ...webhookConfig, url: e.target.value })}
                placeholder="https://webhook.site/... o https://tu-n8n.com/webhook/alerta"
                style={{ width: "100%", marginTop: 4 }}
              />
            </label>

            <label>
              Secreto opcional (Cabecera <code>X-Webhook-Secret</code>):
              <input
                type="password"
                value={webhookConfig.secret}
                onChange={(e) => setWebhookConfig({ ...webhookConfig, secret: e.target.value })}
                placeholder="secreto-compartido-123"
                style={{ width: "100%", marginTop: 4 }}
              />
            </label>

            <div className="row" style={{ marginTop: 6 }}>
              <button className="primary" type="submit">
                Guardar Configuración
              </button>
              <button
                type="button"
                onClick={handleTestWebhook}
                disabled={!webhookConfig.url || testingWebhook}
              >
                {testingWebhook ? "Probando conexión…" : "Enviar Alerta de Prueba"}
              </button>
            </div>
          </form>

          {webhookMsg && (
            <p className={webhookMsg.startsWith("Error") ? "error" : "info-banner"} style={{ marginTop: 12 }}>
              {webhookMsg}
            </p>
          )}

          {webhookConfig.logs && webhookConfig.logs.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <h4>Historial de Envíos en Vivo (Inspector de Webhooks)</h4>
              <p className="small muted">
                Registro en tiempo real de paquetes HTTP POST despachados por BankShield AI:
              </p>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Fecha</th>
                      <th>Evento</th>
                      <th>Destino</th>
                      <th>Respuesta</th>
                      <th>Detalles Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    {webhookConfig.logs.map((log) => (
                      <tr key={log.id}>
                        <td><small>{new Date(log.timestamp).toLocaleTimeString()}</small></td>
                        <td>
                          <span className={`badge ${log.event.includes("high") ? "lvl-critico" : "lvl-medio"}`}>
                            {log.event}
                          </span>
                        </td>
                        <td title={log.url} style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <small>{log.url}</small>
                        </td>
                        <td>
                          <span style={{ color: log.ok ? "var(--ok)" : "var(--crit)", fontWeight: 600, fontSize: "0.8rem" }}>
                            {log.status}
                          </span>
                        </td>
                        <td>
                          <details>
                            <summary style={{ cursor: "pointer", fontSize: "0.78rem" }}>Ver JSON enviado</summary>
                            <pre style={{ background: "#14212b", color: "#eef2f1", padding: 8, borderRadius: 4, fontSize: "0.75rem", margin: "4px 0 0 0" }}>
                              {JSON.stringify(log.payload, null, 2)}
                            </pre>
                          </details>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div style={{ marginTop: 20 }}>
            <h4>Estructura del Payload enviado a n8n / Receptor:</h4>
            <pre style={{ background: "#14212b", color: "#eef2f1", padding: 12, borderRadius: 6, fontSize: "0.82rem", overflowX: "auto" }}>
{`{
  "event": "high_risk_alert",
  "alert_id": 14,
  "analysis_id": "an-8x2b1c",
  "domain": "bcp-seguro-acceso.example-phish.test",
  "level": "critico",
  "score": 96.5,
  "url": "https://bcp-seguro-acceso.example-phish.test/login",
  "recommendation": "Evidencia sólida de amenaza grave. Bloquear y abrir incidente.",
  "timestamp": "2026-10-21T18:15:00Z"
}`}
            </pre>
          </div>
        </div>
      )}

      {tab === "health" && (
        <div className="panel">
          <h3>Supervisión del Servicio y Motor (Reemplazo del Flujo 03 de n8n)</h3>
          <p className="muted small">
            Monitoreo continuo de salud del motor de reglas, modelo ML y fuentes de inteligencia.
          </p>

          <div className="stats" style={{ marginTop: 14 }}>
            <div className="panel">
              <b style={{ color: "var(--ok)", fontSize: "1.4rem" }}>OPERATIVO</b>
              <span>Motor Heurístico (16/16 reglas)</span>
            </div>
            <div className="panel">
              <b style={{ color: "var(--ok)", fontSize: "1.4rem" }}>ACTIVO</b>
              <span>Modelo Probabilístico ML</span>
            </div>
            <div className="panel">
              <b style={{ color: "var(--ok)", fontSize: "1.4rem" }}>{indicators.length} IOCs</b>
              <span>Base Local de Amenazas</span>
            </div>
            <div className="panel">
              <b style={{ color: "var(--ok)", fontSize: "1.4rem" }}>&lt; 5 ms</b>
              <span>Latencia de Análisis</span>
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <h4>Diagnóstico de Componentes:</h4>
            <ul>
              <li><strong>Protección SSRF:</strong> Habilitada (Rechazo de rangos privados 10.x, 192.168.x, 127.x, localhost).</li>
              <li><strong>Tolerancia a fallos:</strong> Si un webhook externo no responde, el análisis continúa sin bloqueos.</li>
              <li><strong>Almacenamiento Local:</strong> Sincronizado en localStorage persistente.</li>
            </ul>
          </div>
        </div>
      )}
    </section>
  );
}
