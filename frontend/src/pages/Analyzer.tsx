import { FormEvent, useState } from "react";
import { api, LEVEL_LABEL } from "../api";

type Result = {
  id: string; url: string; domain: string; level: string; score: number; ml_probability: number | null;
  indicators: { code: string; description: string; points: number }[]; evidence: { source: string; type: string; detail: string }[];
  recommendation: string; explanation: string; data_incomplete: boolean; model_version: string; engine_version: string; latency_ms: number;
};

export default function Analyzer() {
  const [url, setUrl] = useState("");
  const [res, setRes] = useState<Result | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr(""); setRes(null);
    try { setRes(await api<Result>("/analyze", { method: "POST", body: JSON.stringify({ url, operation: "link_review", source_app: "web-ui" }) })); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  }
  return (
    <section>
      <h2>Analizar una URL</h2>
      <p className="muted">El análisis es sintáctico y de reputación: no se visita el sitio. Nunca ingreses contraseñas ni códigos aquí.</p>
      <form onSubmit={submit} className="row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://ejemplo.com/ruta" aria-label="URL a analizar" required maxLength={2048} />
        <button className="primary" disabled={busy}>{busy ? "Analizando…" : "Analizar"}</button>
      </form>
      {err && <p className="error" role="alert">{err}</p>}
      {res && (
        <div className={`panel result lvl-${res.level}`}>
          <div className="head">
            <span className={`badge lvl-${res.level}`}>{LEVEL_LABEL[res.level]}</span>
            <strong>{res.domain}</strong>
            <span className="muted">Puntaje {res.score}/100 · {res.latency_ms} ms</span>
          </div>
          <p>{res.explanation}</p>
          {res.data_incomplete && <p className="warn">Evaluación con datos de inteligencia incompletos: la ausencia de coincidencias no prueba que sea segura.</p>}
          <h3>Indicadores</h3>
          {res.indicators.length ? <ul>{res.indicators.map((i) => <li key={i.code}>{i.description}</li>)}</ul> : <p className="muted">Sin indicadores de riesgo.</p>}
          <h3>Evidencias</h3>
          <ul>{res.evidence.map((e, i) => <li key={i}><b>{e.source}</b>: {e.detail}</li>)}</ul>
          <p className="muted small">ID {res.id} · motor {res.engine_version} · modelo {res.model_version}</p>
        </div>
      )}
    </section>
  );
}
