import { FormEvent, useState } from "react";
import { Analysis } from "../types";
import { db } from "../services/database";
import { LEVEL_ES } from "../services/explainer";

const SAMPLE_URLS = [
  { label: "BCP Oficial (Autorizado)", url: "https://www.viabcp.com/canales/banca-por-internet" },
  { label: "Lookalike BCP (Phishing)", url: "https://bcp-seguro-acceso.example-phish.test/login" },
  { label: "IP Host + Credenciales @", url: "http://banca@185.220.101.5:8080/interbank/login" },
  { label: "TLD Sospechoso .xyz", url: "https://bbva-portal-cliente.xyz/login" },
  { label: "Acortador (bit.ly)", url: "https://bit.ly/3xSecurityVerify" },
];

export default function Analyzer() {
  const [mode, setMode] = useState<"single" | "batch">("single");
  const [url, setUrl] = useState("");
  const [batchText, setBatchText] = useState("");
  const [res, setRes] = useState<Analysis | null>(null);
  const [batchResults, setBatchResults] = useState<{ url: string; analysis?: Analysis; error?: string }[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  function submitSingle(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      const result = db.analyzeUrl(url, "web-ui", "link_review");
      setRes(result);
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function submitBatch(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setBatchResults([]);
    const lines = batchText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    if (lines.length === 0) {
      setErr("Ingresa al menos una URL para el lote.");
      setBusy(false);
      return;
    }

    if (lines.length > 50) {
      setErr("Máximo 50 URLs por lote.");
      setBusy(false);
      return;
    }

    const results: { url: string; analysis?: Analysis; error?: string }[] = [];
    for (const item of lines) {
      try {
        const a = db.analyzeUrl(item, "web-ui-batch", "batch_review");
        results.push({ url: item, analysis: a });
      } catch (ex) {
        results.push({ url: item, error: (ex as Error).message });
      }
    }
    setBatchResults(results);
    setBusy(false);
  }

  return (
    <section>
      <h2>Analizar URL</h2>
      <p className="muted">
        El análisis es sintáctico, heurístico y de reputación: no se visita ni ejecuta el destino. Nunca ingreses contraseñas ni códigos de autenticación aquí.
      </p>

      <div className="subnav">
        <button
          className={mode === "single" ? "active" : ""}
          onClick={() => { setMode("single"); setErr(""); }}
        >
          Análisis Individual
        </button>
        <button
          className={mode === "batch" ? "active" : ""}
          onClick={() => { setMode("batch"); setErr(""); }}
        >
          Análisis por Lote
        </button>
      </div>

      {mode === "single" ? (
        <>
          <div className="quick-tests">
            <span>Ejemplos rápidos:</span>
            {SAMPLE_URLS.map((s) => (
              <button
                key={s.label}
                type="button"
                className="chip"
                onClick={() => setUrl(s.url)}
              >
                {s.label}
              </button>
            ))}
          </div>

          <form onSubmit={submitSingle} className="row">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://ejemplo.com/ruta"
              aria-label="URL a analizar"
              required
              maxLength={2048}
            />
            <button className="primary" disabled={busy}>
              {busy ? "Analizando…" : "Analizar"}
            </button>
          </form>

          {err && <p className="error" role="alert">{err}</p>}

          {res && (
            <div className={`panel result lvl-${res.level}`}>
              <div className="head">
                <span className={`badge lvl-${res.level}`}>{LEVEL_ES[res.level] || res.level}</span>
                <strong>{res.domain}</strong>
                <span className="muted">
                  Puntaje {res.score}/100 · Latencia {res.latency_ms} ms
                </span>
                {res.ml_probability !== null && (
                  <span className="muted small">
                    (ML Phish: {(res.ml_probability * 100).toFixed(1)}%)
                  </span>
                )}
              </div>

              <p style={{ marginTop: 10, lineHeight: 1.6 }}>{res.explanation}</p>

              {res.data_incomplete && (
                <p className="warn">
                  Evaluación con datos de inteligencia incompletos: la ausencia de coincidencias no prueba que sea segura.
                </p>
              )}

              <h3>Indicadores detectados ({res.indicators.length})</h3>
              {res.indicators.length ? (
                <ul>
                  {res.indicators.map((i, idx) => (
                    <li key={idx}>
                      <b>+{i.points} pts</b> — {i.description}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">Sin indicadores sospechosos detectados.</p>
              )}

              <h3>Trazabilidad de Evidencias ({res.evidence.length})</h3>
              <ul>
                {res.evidence.map((e, i) => (
                  <li key={i}>
                    <b>{e.source}</b> ({e.type}): {e.detail}
                  </li>
                ))}
              </ul>

              <p className="muted small" style={{ marginTop: 12, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
                ID: {res.id} · Motor: {res.engine_version} · Modelo: {res.model_version} · Operación: {res.operation}
              </p>
            </div>
          )}
        </>
      ) : (
        <>
          <form onSubmit={submitBatch} style={{ display: "grid", gap: 10, marginTop: 12 }}>
            <label className="muted small">
              Ingresa una URL por línea (máximo 50):
              <textarea
                rows={5}
                value={batchText}
                onChange={(e) => setBatchText(e.target.value)}
                placeholder="https://viabcp.com&#10;https://bbva-portal-cliente.xyz/login&#10;http://185.220.101.5/banca"
                style={{ width: "100%", marginTop: 4 }}
                required
              />
            </label>
            <div>
              <button className="primary" disabled={busy}>
                {busy ? "Procesando lote…" : "Analizar Lote de URLs"}
              </button>
            </div>
          </form>

          {err && <p className="error" role="alert">{err}</p>}

          {batchResults.length > 0 && (
            <div className="panel" style={{ marginTop: 16 }}>
              <h3>Resultados del Lote ({batchResults.length} procesadas)</h3>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>URL evaluada</th>
                      <th>Nivel</th>
                      <th>Puntaje</th>
                      <th>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batchResults.map((r, idx) => (
                      <tr key={idx}>
                        <td style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.url}>
                          {r.url}
                        </td>
                        <td>
                          {r.analysis ? (
                            <span className={`badge lvl-${r.analysis.level}`}>
                              {LEVEL_ES[r.analysis.level] || r.analysis.level}
                            </span>
                          ) : (
                            <span className="error">Error</span>
                          )}
                        </td>
                        <td>{r.analysis ? `${r.analysis.score}/100` : "—"}</td>
                        <td>
                          {r.analysis ? (
                            <span className="small">{r.analysis.recommendation.slice(0, 60)}…</span>
                          ) : (
                            <span className="error small">{r.error}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
