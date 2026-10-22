import { FormEvent, useState } from "react";
import { Role, User } from "../types";
import { db } from "../services/database";

export default function Users() {
  const [users, setUsers] = useState<User[]>(db.getUsers());
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [msg, setMsg] = useState("");
  const currentUser = db.getCurrentUser();

  function reload() {
    setUsers(db.getUsers());
  }

  function handleCreate(e: FormEvent) {
    e.preventDefault();
    setMsg("");
    try {
      db.createUser(email, name, role);
      db.logAudit("user_create", currentUser?.email || "admin", `user:${email}`, "ok", `Rol: ${role}`);
      setEmail("");
      setName("");
      reload();
      setMsg("Usuario creado exitosamente.");
    } catch (err) {
      setMsg(`Error: ${(err as Error).message}`);
    }
  }

  function toggleActive(userId: number, currentActive: boolean) {
    setMsg("");
    try {
      db.setUserActive(userId, !currentActive, currentUser?.id || 1);
      db.logAudit("user_active", currentUser?.email || "admin", `user_id:${userId}`, "ok", `Nuevo estado activo: ${!currentActive}`);
      reload();
    } catch (err) {
      setMsg(`Error: ${(err as Error).message}`);
    }
  }

  return (
    <section>
      <h2>Gestión de Usuarios y Roles</h2>
      <p className="muted">
        Administración de cuentas con control de acceso basado en roles (RBAC: Admin, Analyst, Operator, Auditor, Manager).
      </p>

      {msg && (
        <p className={msg.startsWith("Error") ? "error" : "info-banner"}>
          {msg}
        </p>
      )}

      <div className="panel" style={{ marginBottom: 16 }}>
        <h3>Registrar Nuevo Usuario</h3>
        <form onSubmit={handleCreate} className="row">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="usuario@bankshield.local"
            required
          />
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Nombre completo"
            required
          />
          <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="admin">Administrador (admin)</option>
            <option value="analyst">Analista SOC (analyst)</option>
            <option value="operator">Operador (operator)</option>
            <option value="auditor">Auditor (auditor)</option>
            <option value="manager">Gerente de Riesgo (manager)</option>
          </select>
          <button className="primary" type="submit">
            Crear Usuario
          </button>
        </form>
      </div>

      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Nombre</th>
              <th>Correo electrónico</th>
              <th>Rol asignado</th>
              <th>Estado</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td><strong>{u.full_name}</strong></td>
                <td>{u.email}</td>
                <td>
                  <span className="chip role-chip">
                    {u.role.toUpperCase()}
                  </span>
                </td>
                <td>
                  <span style={{ color: u.is_active ? "var(--ok)" : "var(--crit)", fontWeight: 600 }}>
                    {u.is_active ? "Activo" : "Inactivo"}
                  </span>
                </td>
                <td>
                  {u.id !== currentUser?.id ? (
                    <button
                      className="chip"
                      onClick={() => toggleActive(u.id, u.is_active)}
                    >
                      {u.is_active ? "Desactivar" : "Activar"}
                    </button>
                  ) : (
                    <span className="muted small">(Cuenta actual)</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
