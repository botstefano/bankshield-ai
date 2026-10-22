import { useState } from "react";
import { Role, User } from "./types";
import { db } from "./services/database";
import Login from "./pages/Login";
import Analyzer from "./pages/Analyzer";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";
import Intel from "./pages/Intel";
import Users from "./pages/Users";

const PERMS: Record<string, Role[]> = {
  analyzer: ["admin", "analyst", "operator"],
  dashboard: ["admin", "analyst", "auditor", "manager"],
  alerts: ["admin", "analyst", "auditor", "manager"],
  audit: ["admin", "auditor"],
  intel: ["admin", "analyst"],
  users: ["admin"],
};

const TABS = [
  ["analyzer", "Analizar URL"],
  ["dashboard", "Panel"],
  ["alerts", "Alertas"],
  ["audit", "Auditoría"],
  ["intel", "Inteligencia"],
  ["users", "Usuarios"],
] as const;

export default function App() {
  const [user, setUser] = useState<User | null>(db.getCurrentUser());
  const [tab, setTab] = useState<string>("analyzer");

  if (!user) {
    return (
      <Login
        onLogin={(u) => {
          setUser(u);
          setTab(PERMS.analyzer.includes(u.role) ? "analyzer" : "dashboard");
        }}
      />
    );
  }

  const visible = TABS.filter(([k]) => PERMS[k].includes(user.role));
  const current = visible.some(([k]) => k === tab) ? tab : visible[0]?.[0];

  function handleLogout() {
    db.logAudit("logout", user?.email || "", "auth", "ok", "Cierre de sesión manual");
    db.setCurrentUser(null);
    setUser(null);
  }

  return (
    <div className="shell">
      <header>
        <div className="brand">
          <span className="mark" aria-hidden />
          BankShield AI
        </div>
        <nav>
          {visible.map(([k, l]) => (
            <button
              key={k}
              className={k === current ? "on" : ""}
              onClick={() => setTab(k)}
            >
              {l}
            </button>
          ))}
        </nav>
        <div className="who">
          <span>{user.email}</span>
          <span style={{ opacity: 0.6 }}>·</span>
          <span style={{ textTransform: "uppercase", fontSize: "0.75rem", background: "rgba(255,255,255,0.15)", padding: "1px 6px", borderRadius: 4 }}>
            {user.role}
          </span>
          <button className="link" onClick={handleLogout}>
            Cerrar sesión
          </button>
        </div>
      </header>
      <main>
        {current === "analyzer" && <Analyzer />}
        {current === "dashboard" && <Dashboard />}
        {current === "alerts" && (
          <Alerts canEdit={["admin", "analyst"].includes(user.role)} />
        )}
        {current === "audit" && <Audit />}
        {current === "intel" && <Intel />}
        {current === "users" && <Users />}
      </main>
    </div>
  );
}
