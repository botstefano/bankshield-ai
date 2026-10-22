import { useEffect, useState } from "react";
import { DashboardSummary } from "../types";
import { db } from "../services/database";
import { LEVEL_ES } from "../services/explainer";
import { exportReport } from "../services/reports";

export default function Dashboard() {
  const [s, setS] = useState<DashboardSummary | null>(null);

  useEffect(() => {
    setS(db.getDashboardSummary());
  }, []);

  if (!s) return <p className="muted">Cargando métricas de seguridad…</p>;

  const maxL = Math.max(1, ...Object.values(s.by_level));
  const maxD = Math.max(1, ...Object.values(s.per_day));

  return (
    <section>
      <h2>Panel de seguridad</h2>

      {s.model.is_demo && (
        <p className="warn">
          El modelo ML activo ({s.model.version}) opera con calibración sintética de demostración. Entrena con telemetría bancaria real antes de transferir a producción.
        </p>
      )}

      <div className="stats">
        <div className="panel">
          <b>{s.total}</b>
          <span>URL analizadas</span>
        </div>
        <div className="panel">
          <b>{s.open_alerts}</b>
          <span>Alertas pendientes</span>
        </div>
        <div className="panel">
          <b>{s.latency_avg_ms} ms</b>
          <span>Latencia media</span>
        </div>
        <div className="panel">
          <b>{s.latency_p95_ms} ms</b>
          <span>Latencia p95 (7 días)</span>
        </div>
      </div>

      <div className="grid2">
        <div className="panel">
          <h3>Análisis por nivel de riesgo</h3>
          {Object.entries(s.by_level).map(([k, v]) => (
            <div className="bar" key={k}>
              <span>{LEVEL_ES[k] ?? k}</span>
              <i
                className={`lvl-${k}`}
                style={{ width: `${(v / maxL) * 100}%` }}
              />
              <em>{v}</em>
            </div>
          ))}
          {!Object.keys(s.by_level).length && (
            <p className="muted">Aún no hay análisis registrados.</p>
          )}
        </div>

        <div className="panel">
          <h3>Volumen últimos 7 días</h3>
          <div className="cols">
            {Object.entries(s.per_day).map(([d, v]) => (
              <div key={d}>
                <i
                  style={{ height: `${(v / maxD) * 100}%` }}
                  title={`${d}: ${v} análisis`}
                />
                <span>{d.slice(5)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <h3>Exportación de Informes de Cumplimiento</h3>
        <p className="muted small" style={{ margin: "4px 0 12px 0" }}>
          Genera reportes técnicos y ejecutivos para auditoría regulatoria bancaria:
        </p>
        <div className="row">
          <button className="primary" onClick={() => exportReport("pdf")}>
            Descargar PDF
          </button>
          <button onClick={() => exportReport("docx")}>
            Descargar Word (.docx)
          </button>
          <button onClick={() => exportReport("xlsx")}>
            Descargar Excel (.csv/.xlsx)
          </button>
        </div>
      </div>

      <p className="muted small">
        Una caída en el número de alertas no implica mayor seguridad: también puede indicar pérdida de capacidad de detección o alteración de feeds de inteligencia.
      </p>
    </section>
  );
}
