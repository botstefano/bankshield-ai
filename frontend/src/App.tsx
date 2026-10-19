import { useEffect, useState } from "react";
import { session, User } from "./api";
import Login from "./pages/Login";
import Analyzer from "./pages/Analyzer";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";

const PERMS: Record<string, string[]> = {
  analyzer: ["admin", "analyst", "operator"],
  dashboard: ["admin", "analyst", "auditor", "manager"],
  alerts: ["admin", "analyst", "auditor", "manager"],
  audit: ["admin", "auditor"],
};
const TABS = [["analyzer", "Analizar URL"], ["dashboard", "Panel"], ["alerts", "Alertas"], ["audit", "Auditoría"]] as const;

export default function App() {
  const [user, setUser] = useState<User | null>(session.user);
  const [tab, setTab] = useState<string>("analyzer");
  useEffect(() => { const f = () => setUser(null); window.addEventListener("bs-logout", f); return () => window.removeEventListener("bs-logout", f); }, []);
  if (!user) return <Login onLogin={(u) => { setUser(u); setTab(PERMS.analyzer.includes(u.role) ? "analyzer" : "dashboard"); }} />;
  const visible = TABS.filter(([k]) => PERMS[k].includes(user.role));
  const current = visible.some(([k]) => k === tab) ? tab : visible[0]?.[0];
  return (
    <div className="shell">
      <header>
        <div className="brand"><span className="mark" aria-hidden />BankShield AI</div>
        <nav>{visible.map(([k, l]) => <button key={k} className={k === current ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}</nav>
        <div className="who">{user.email} · {user.role}<button className="link" onClick={() => { session.clear(); setUser(null); }}>Cerrar sesión</button></div>
      </header>
      <main>
        {current === "analyzer" && <Analyzer />}
        {current === "dashboard" && <Dashboard />}
        {current === "alerts" && <Alerts canEdit={["admin", "analyst"].includes(user.role)} />}
        {current === "audit" && <Audit />}
      </main>
    </div>
  );
}
