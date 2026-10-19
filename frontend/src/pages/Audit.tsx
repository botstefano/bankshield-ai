import { useEffect, useState } from "react";
import { api } from "../api";

type Ev = { id: number; ts: string; user: string; action: string; resource: string; outcome: string; ip: string };

export default function Audit() {
  const [rows, setRows] = useState<Ev[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => { api<Ev[]>("/audit/events?limit=200").then(setRows).catch((e) => setErr(e.message)); }, []);
  return (
    <section>
      <h2>Auditoría</h2>
      {err && <p className="error">{err}</p>}
      <div className="scroll"><table>
        <thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Recurso</th><th>Resultado</th><th>IP</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.id}><td>{new Date(r.ts).toLocaleString()}</td><td>{r.user}</td><td>{r.action}</td><td>{r.resource}</td><td>{r.outcome}</td><td>{r.ip}</td></tr>)}</tbody>
      </table></div>
    </section>
  );
}
