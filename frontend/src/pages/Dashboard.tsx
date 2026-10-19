import { useEffect, useState } from "react";
import { api, download, LEVEL_LABEL } from "../api";

type Summary = {
  total: number; by_level: Record<string, number>; open_alerts: number; per_day: Record<string, number>;
  latency_avg_ms: number; latency_p95_ms: number; model: { version: string; is_demo: boolean };
};

export default function Dashboard() {
  const [s, setS] = useState<Summary | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api<Summary>("/dashboard/summary").then(setS).catch((e) => setErr(e.message)); }, []);
  if (err) return <p className="error">{err}</p>;
  if (!s) return <p className="muted">Cargando…</p>;
  const maxL = Math.max(1, ...Object.values(s.by_level));
  const maxD = Math.max(1, ...Object.values(s.per_day));
  return (
    <section>
      <h2>Panel de seguridad</h2>
      {s.model.is_demo && <p className="warn">El modelo ML activo fue entrenado con datos sintéticos de demostración. Entrena con un dataset real antes de usarlo en producción.</p>}
      <div className="stats">
        <div className="panel"><b>{s.total}</b><span>URL analizadas</span></div>
        <div className="panel"><b>{s.open_alerts}</b><span>Alertas pendientes</span></div>
        <div className="panel"><b>{s.latency_avg_ms} ms</b><span>Latencia media</span></div>
        <div className="panel"><b>{s.latency_p95_ms} ms</b><span>Latencia p95 (7 días)</span></div>
      </div>
      <div className="grid2">
        <div className="panel"><h3>Análisis por nivel</h3>
          {Object.entries(s.by_level).map(([k, v]) => (
            <div className="bar" key={k}><span>{LEVEL_LABEL[k] ?? k}</span><i className={`lvl-${k}`} style={{ width: `${(v / maxL) * 100}%` }} /><em>{v}</em></div>))}
          {!Object.keys(s.by_level).length && <p className="muted">Aún no hay análisis.</p>}
        </div>
        <div className="panel"><h3>Últimos 7 días</h3>
          <div className="cols">{Object.entries(s.per_day).map(([d, v]) => (
            <div key={d}><i style={{ height: `${(v / maxD) * 100}%` }} title={`${v}`} /><span>{d.slice(5)}</span></div>))}</div>
        </div>
      </div>
      <div className="row">
        <button onClick={() => download("pdf")}>Descargar PDF</button>
        <button onClick={() => download("docx")}>Descargar Word</button>
        <button onClick={() => download("xlsx")}>Descargar Excel</button>
      </div>
      <p className="muted small">Una caída en el número de alertas no implica mayor seguridad: también puede indicar pérdida de capacidad de detección.</p>
    </section>
  );
}
