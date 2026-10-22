import { FormEvent, useState } from "react";
import { ThreatIndicator } from "../types";
import { db } from "../services/database";

export default function Intel() {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>(db.getThreatIndicators());
  const [newUrl, setNewUrl] = useState("");
  const [newSource, setNewSource] = useState("manual");
  const [newKind, setNewKind] = useState("phishing");
  const [message, setMessage] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

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
      // Simulate feed synchronization
      db.addThreatIndicator("http://interbank-renovacion.top/validar", "feed-cert-peru", "phishing");
      db.addThreatIndicator("https://scotiabank-online-validacion.com/login", "feed-phishtank", "phishing");
      setIndicators(db.getThreatIndicators());
      setIsRefreshing(false);
      setMessage("Feeds de amenazas sincronizados exitosamente (feed-cert-peru, feed-openphish, feed-phishtank).");
    }, 600);
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
      <h2>Inteligencia de Amenazas (Threat Intel)</h2>
      <p className="muted">
        Capa desacoplada de indicadores maliciosos conocidos (IoCs). La consulta se realiza de forma estrictamente local para no filtrar destinos sospechosos a terceros.
      </p>

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
          <div style={{ marginTop: 12 }}>
            <button disabled={isRefreshing} onClick={handleRefresh}>
              {isRefreshing ? "Sincronizando feeds…" : "Refrescar Feeds Externos"}
            </button>
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
    </section>
  );
}
