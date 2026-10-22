import { useEffect, useState } from "react";
import { Alert, AlertStatus, Analysis } from "../types";
import { db } from "../services/database";
import { LEVEL_ES } from "../services/explainer";

const STATUSES: [AlertStatus, string][] = [
  ["open", "Abierta"],
  ["investigating", "En investigación"],
  ["confirmed", "Confirmada"],
  ["false_positive", "Falso positivo"],
  ["resolved", "Resuelta"],
];

interface AlertsProps {
  canEdit: boolean;
}

export default function Alerts({ canEdit }: AlertsProps) {
  const [rows, setRows] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<string>("");
  const [selectedAnalysis, setSelectedAnalysis] = useState<Analysis | null>(null);

  function load() {
    setRows(db.getAlerts(filter || undefined));
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 4000);
    return () => clearInterval(interval);
  }, [filter]);

  function handleStatusChange(id: number, newStatus: string) {
    db.updateAlert(id, { status: newStatus as AlertStatus });
    load();
  }

  function viewDetails(alertId: number) {
    const detail = db.getAlertById(alertId);
    if (detail && detail.analysis) {
      setSelectedAnalysis(detail.analysis);
    }
  }

  return (
    <section>
      <h2>Centro de alertas de ciberseguridad</h2>
      <p className="muted">
        Las alertas se generan automáticamente cuando un análisis alcanza riesgo <strong>Alto</strong> o <strong>Crítico</strong>.
      </p>

      <div className="row">
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Filtrar por estado"
        >
          <option value="">Todos los estados</option>
          {STATUSES.map(([k, l]) => (
            <option key={k} value={k}>
              {l}
            </option>
          ))}
        </select>
        <span className="muted small">
          Mostrando {rows.length} alerta{rows.length === 1 ? "" : "s"}
        </span>
      </div>

      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Dominio</th>
              <th>Nivel</th>
              <th>Puntaje</th>
              <th>Estado</th>
              <th>Detalle</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td>{new Date(a.created_at).toLocaleString()}</td>
                <td title={a.url}>
                  <strong>{a.domain || "Desconocido"}</strong>
                  {a.url && (
                    <div className="muted small" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.url}
                    </div>
                  )}
                </td>
                <td>
                  <span className={`badge lvl-${a.level}`}>
                    {LEVEL_ES[a.level] || a.level}
                  </span>
                </td>
                <td>{a.score}</td>
                <td>
                  {canEdit ? (
                    <select
                      value={a.status}
                      onChange={(e) => handleStatusChange(a.id, e.target.value)}
                    >
                      {STATUSES.map(([k, l]) => (
                        <option key={k} value={k}>
                          {l}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span>{STATUSES.find(([k]) => k === a.status)?.[1] || a.status}</span>
                  )}
                </td>
                <td>
                  <button
                    className="chip"
                    onClick={() => viewDetails(a.id)}
                    style={{ fontSize: "0.75rem" }}
                  >
                    Examinar
                  </button>
                </td>
              </tr>
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={6} className="muted" style={{ textAlign: "center", padding: 24 }}>
                  Sin alertas en este filtro. Se registran automáticamente ante amenazas detectadas.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedAnalysis && (
        <div className="modal-backdrop" onClick={() => setSelectedAnalysis(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setSelectedAnalysis(null)}>
              ✕
            </button>
            <div className="head" style={{ marginBottom: 12 }}>
              <span className={`badge lvl-${selectedAnalysis.level}`}>
                {LEVEL_ES[selectedAnalysis.level] || selectedAnalysis.level}
              </span>
              <h3 style={{ margin: 0 }}>{selectedAnalysis.domain}</h3>
              <span className="muted">Puntaje {selectedAnalysis.score}/100</span>
            </div>

            <p><strong>URL Completa:</strong> <code style={{ wordBreak: "break-all" }}>{selectedAnalysis.url}</code></p>
            <p><strong>Explicación:</strong> {selectedAnalysis.explanation}</p>
            <p><strong>Recomendación:</strong> {selectedAnalysis.recommendation}</p>

            <h4>Indicadores ({selectedAnalysis.indicators.length})</h4>
            <ul>
              {selectedAnalysis.indicators.map((i, idx) => (
                <li key={idx}>
                  <b>+{i.points} pts</b> — {i.description}
                </li>
              ))}
            </ul>

            <h4>Evidencias Registradas</h4>
            <ul>
              {selectedAnalysis.evidence.map((e, idx) => (
                <li key={idx}>
                  <b>{e.source}</b> ({e.type}): {e.detail}
                </li>
              ))}
            </ul>

            <div style={{ textAlign: "right", marginTop: 16 }}>
              <button className="primary" onClick={() => setSelectedAnalysis(null)}>
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
