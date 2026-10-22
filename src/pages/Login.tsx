import { FormEvent, useState } from "react";
import { User, Role } from "../types";
import { db } from "../services/database";

interface LoginProps {
  onLogin: (u: User) => void;
}

const DEMO_PRESETS: { email: string; role: Role; label: string }[] = [
  { email: "admin@bankshield.local", role: "admin", label: "Administrador (Full)" },
  { email: "analyst@bankshield.local", role: "analyst", label: "Analista SOC L2" },
  { email: "operator@bankshield.local", role: "operator", label: "Operador de Mesa" },
  { email: "auditor@bankshield.local", role: "auditor", label: "Auditor" },
  { email: "manager@bankshield.local", role: "manager", label: "Gerente de Riesgo" },
];

export default function Login({ onLogin }: LoginProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  function executeLogin(userEmail: string) {
    setBusy(true);
    setErr("");
    try {
      const user = db.getUserByEmail(userEmail);
      if (!user) {
        db.logAudit("login", userEmail, "auth", "fail", "Usuario no encontrado");
        throw new Error("Credenciales inválidas o usuario no registrado.");
      }
      if (!user.is_active) {
        db.logAudit("login", userEmail, "auth", "fail", "Cuenta inactiva");
        throw new Error("La cuenta se encuentra inactiva. Contacta al administrador.");
      }
      db.setCurrentUser(user);
      db.logAudit("login", user.email, "auth", "ok", `Inicio de sesión exitoso con rol ${user.role}`);
      onLogin(user);
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    executeLogin(email);
  }

  return (
    <div className="login">
      <form onSubmit={submit} className="panel">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="mark" aria-hidden style={{ width: 22, height: 26 }} />
          <div>
            <h1 style={{ margin: 0, fontSize: "1.4rem" }}>BankShield AI</h1>
            <p className="muted small" style={{ margin: 0 }}>Detección de phishing en procesos bancarios</p>
          </div>
        </div>

        <div style={{ marginTop: 12 }}>
          <label>
            Correo institucional
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analista@bankshield.local"
              required
              autoFocus
            />
          </label>
        </div>

        <div>
          <label>
            Contraseña
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
            />
          </label>
        </div>

        {err && <p className="error" role="alert">{err}</p>}

        <button className="primary" disabled={busy} type="submit" style={{ marginTop: 4 }}>
          {busy ? "Ingresando…" : "Ingresar a la plataforma"}
        </button>

        <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
          <p className="small muted" style={{ margin: "0 0 6px 0", fontWeight: 600 }}>
            Acceso Rápido por Rol (Demostración):
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {DEMO_PRESETS.map((p) => (
              <button
                key={p.email}
                type="button"
                className="chip role-chip"
                style={{ textAlign: "left", justifyContent: "space-between", padding: "6px 10px" }}
                onClick={() => {
                  setEmail(p.email);
                  setPassword("Demo#2026-Cambiar");
                  executeLogin(p.email);
                }}
              >
                <span><b>{p.label}</b></span>
                <span className="muted small">{p.email}</span>
              </button>
            ))}
          </div>
        </div>
      </form>
    </div>
  );
}
