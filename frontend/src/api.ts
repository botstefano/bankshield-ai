const BASE = "/api/v1";
export type User = { id: number; email: string; full_name: string; role: string };

export const session = {
  get token() { return localStorage.getItem("bs_token"); },
  get user(): User | null { const u = localStorage.getItem("bs_user"); return u ? JSON.parse(u) : null; },
  set(token: string, user: User) { localStorage.setItem("bs_token", token); localStorage.setItem("bs_user", JSON.stringify(user)); },
  clear() { localStorage.removeItem("bs_token"); localStorage.removeItem("bs_user"); },
};

async function errorText(r: Response): Promise<string> {
  try {
    const j = await r.json();
    if (typeof j.detail === "string") return j.detail;
    if (Array.isArray(j.detail)) return j.detail.map((d: { msg: string }) => d.msg).join("; ");
  } catch { /* sin cuerpo JSON */ }
  return `Error ${r.status}`;
}

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(opts.headers as Record<string, string>) };
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  const r = await fetch(BASE + path, { ...opts, headers });
  if (r.status === 401 && session.token) { session.clear(); window.dispatchEvent(new Event("bs-logout")); }
  if (!r.ok) throw new Error(await errorText(r));
  return r.json() as Promise<T>;
}

export async function download(format: string) {
  const r = await fetch(`${BASE}/reports/download?format=${format}`, { headers: { Authorization: `Bearer ${session.token}` } });
  if (!r.ok) throw new Error(await errorText(r));
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url; a.download = `bankshield-reporte.${format}`; a.click();
  URL.revokeObjectURL(url);
}

export const LEVEL_LABEL: Record<string, string> = {
  seguro_provisional: "Seguro provisional", bajo: "Bajo", medio: "Medio", alto: "Alto", critico: "Crítico", desconocido: "Desconocido",
};
