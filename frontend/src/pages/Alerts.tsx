import { useCallback, useEffect, useState } from "react";
import { api, LEVEL_LABEL } from "../api";

type Alert = { id: number; level: string; status: string; domain: string; url: string; score: number; created_at: string; note: string };
const STATUSES = [["open", "Abierta"], ["investigating", "En investigación"], ["confirmed", "Confirmada"], ["false_positive", "Falso positivo"], ["resolved", "Resuelta"]];

export default function Alerts({ canEdit }: { canEdit: boolean }) {
  const [rows, setRows] = useState<Alert[]>([]);
  const [filter, setFilter] = useState("");
  const [err, setErr] = useState("");
  const load = useCallback(() => {
    api<Alert[]>(`/alerts${filter ? `?status=${filter}` : ""}`).then(setRows).catch((e) => setErr(e.message));
  }, [filter]);
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]); // actualización periódica
  async function setStatus(id: number, status: string) {
    try { await api(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }); load(); } catch (e) { setErr((e as Error).message); }
  }
  return (
    <section>
      <h2>Centro de alertas</h2>
      <div className="row">
        <select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filtrar por estado">
          <option value="">Todos los estados</option>{STATUSES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </div>
      {err && <p className="error">{err}</p>}
      <div className="scroll"><table>
        <thead><tr><th>Fecha</th><th>Dominio</th><th>Nivel</th><th>Puntaje</th><th>Estado</th></tr></thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id}>
              <td>{new Date(a.created_at).toLocaleString()}</td><td title={a.url}>{a.domain}</td>
              <td><span className={`badge lvl-${a.level}`}>{LEVEL_LABEL[a.level]}</span></td><td>{a.score}</td>
              <td>{canEdit ? <select value={a.status} onChange={(e) => setStatus(a.id, e.target.value)}>{STATUSES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
                : STATUSES.find(([k]) => k === a.status)?.[1]}</td>
            </tr>))}
          {!rows.length && <tr><td colSpan={5} className="muted">Sin alertas. Se crean automáticamente con riesgo alto o crítico.</td></tr>}
        </tbody>
      </table></div>
    </section>
  );
}
