import { FormEvent, useState } from "react";
import { api, session, User } from "../api";

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      const r = await api<{ access_token: string; user: User }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      session.set(r.access_token, r.user); onLogin(r.user);
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  }
  return (
    <div className="login">
      <form onSubmit={submit} className="panel">
        <h1>BankShield AI</h1>
        <p className="muted">Detección de phishing en procesos bancarios</p>
        <label>Correo<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus /></label>
        <label>Contraseña<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        {err && <p className="error" role="alert">{err}</p>}
        <button className="primary" disabled={busy}>{busy ? "Ingresando…" : "Ingresar"}</button>
      </form>
    </div>
  );
}
