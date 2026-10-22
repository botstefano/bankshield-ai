import { useEffect, useState } from "react";
import { AuditLog } from "../types";
import { db } from "../services/database";

export default function Audit() {
  const [rows, setRows] = useState<AuditLog[]>([]);
  const [filterAction, setFilterAction] = useState("");

  function load() {
    let logs = db.getAuditLogs(200);
    if (filterAction) {
      logs = logs.filter((l) => l.action.includes(filterAction.toLowerCase()));
    }
    setRows(logs);
  }

  useEffect(() => {
    load();
  }, [filterAction]);

  return (
    <section>
      <h2>Registro de auditoría inmutable</h2>
      <p className="muted">
        Trazabilidad estricta de accesos, decisiones de mitigación y cambios de estado en alertas de seguridad.
      </p>

      <div className="row">
        <input
          type="search"
          placeholder="Filtrar por acción (login, analyze, alert_update...)"
          value={filterAction}
          onChange={(e) => setFilterAction(e.target.value)}
          style={{ maxWidth: 360 }}
        />
        <span className="muted small">
          Mostrando {rows.length} eventos registrados
        </span>
      </div>

      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Usuario</th>
              <th>Acción</th>
              <th>Recurso</th>
              <th>Resultado</th>
              <th>IP</th>
              <th>Detalle</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.ts).toLocaleString()}</td>
                <td>{r.user}</td>
                <td>
                  <code style={{ background: "#eef2f1", padding: "2px 4px", borderRadius: 3 }}>
                    {r.action}
                  </code>
                </td>
                <td>{r.resource}</td>
                <td>
                  <span style={{
                    color: r.outcome === "ok" ? "var(--ok)" : "var(--crit)",
                    fontWeight: 600,
                    textTransform: "uppercase",
                    fontSize: "0.8rem"
                  }}>
                    {r.outcome}
                  </span>
                </td>
                <td><small>{r.ip}</small></td>
                <td style={{ maxWidth: 280, fontSize: "0.82rem" }}>{r.detail}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={7} className="muted" style={{ textAlign: "center", padding: 20 }}>
                  No se encontraron eventos de auditoría con los criterios seleccionados.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
