import {
  Alert,
  AlertStatus,
  Analysis,
  AuditLog,
  DashboardSummary,
  RiskLevel,
  Role,
  ThreatIndicator,
  User,
} from "../types";
import { assessUrl, ThreatLookupResult } from "./riskEngine";

const STORAGE_KEY = "bankshield_db_v1";
const SESSION_KEY = "bankshield_session_user";

export const PERMISSIONS: Record<Role, string[]> = {
  admin: ["*"],
  analyst: ["analyze", "analysis:read_all", "alerts:read", "alerts:write", "dashboard", "reports", "intel:write"],
  operator: ["analyze"],
  auditor: ["audit:read", "reports", "dashboard", "alerts:read", "analysis:read_all"],
  manager: ["dashboard", "reports", "alerts:read"],
};

export function hasPermission(role: Role, perm: string): boolean {
  const allowed = PERMISSIONS[role] || [];
  return allowed.includes("*") || allowed.includes(perm);
}

interface StoredData {
  users: User[];
  threatIndicators: ThreatIndicator[];
  analyses: Analysis[];
  alerts: Alert[];
  auditLogs: AuditLog[];
  nextAlertId: number;
  nextAuditId: number;
  nextIndicatorId: number;
}

function getInitialData(): StoredData {
  const now = new Date();
  const isoNow = now.toISOString();

  const users: User[] = [
    { id: 1, email: "admin@bankshield.local", full_name: "Administrador de Seguridad", role: "admin", is_active: true, created_at: isoNow },
    { id: 2, email: "analyst@bankshield.local", full_name: "Analista SOC L2", role: "analyst", is_active: true, created_at: isoNow },
    { id: 3, email: "operator@bankshield.local", full_name: "Operador de Mesa", role: "operator", is_active: true, created_at: isoNow },
    { id: 4, email: "auditor@bankshield.local", full_name: "Auditor Interno de Ciberseguridad", role: "auditor", is_active: true, created_at: isoNow },
    { id: 5, email: "manager@bankshield.local", full_name: "Gerente de Riesgo Operacional", role: "manager", is_active: true, created_at: isoNow },
  ];

  const threatIndicators: ThreatIndicator[] = [
    { id: 1, url_norm: "http://bcp-seguro-acceso.example-phish.test/login", host: "bcp-seguro-acceso.example-phish.test", source: "feed-cert-peru", kind: "phishing", added_at: isoNow },
    { id: 2, url_norm: "https://viabcp-verifica.example-phish.test/clave", host: "viabcp-verifica.example-phish.test", source: "feed-openphish", kind: "phishing", added_at: isoNow },
    { id: 3, url_norm: "https://bbva-portal-cliente.xyz/login", host: "bbva-portal-cliente.xyz", source: "manual", kind: "credential-theft", added_at: isoNow },
    { id: 4, url_norm: "http://interbank-renovacion.top/validar", host: "interbank-renovacion.top", source: "feed-phishtank", kind: "phishing", added_at: isoNow },
  ];

  // Generate seed analyses across 7 days
  const analyses: Analysis[] = [];
  const alerts: Alert[] = [];
  let alertSeq = 1;

  const sampleItems: { url: string; level: RiskLevel; score: number; domain: string; daysAgo: number }[] = [
    { url: "https://www.viabcp.com/canales/banca-por-internet", level: "seguro_provisional", score: 0.0, domain: "viabcp.com", daysAgo: 6 },
    { url: "https://bcp-seguro-acceso.example-phish.test/login", level: "critico", score: 96.5, domain: "bcp-seguro-acceso.example-phish.test", daysAgo: 5 },
    { url: "http://185.220.101.5/banca/login", level: "alto", score: 78.4, domain: "185.220.101.5", daysAgo: 5 },
    { url: "https://interbank.pe/personas", level: "seguro_provisional", score: 0.0, domain: "interbank.pe", daysAgo: 4 },
    { url: "https://bit.ly/3xAuthBankSecurity", level: "medio", score: 42.0, domain: "bit.ly", daysAgo: 4 },
    { url: "https://bbva-portal-cliente.xyz/login", level: "critico", score: 98.2, domain: "bbva-portal-cliente.xyz", daysAgo: 3 },
    { url: "https://bbva.pe/personas", level: "seguro_provisional", score: 0.0, domain: "bbva.pe", daysAgo: 3 },
    { url: "https://scotiabank.com.pe/personas", level: "seguro_provisional", score: 0.0, domain: "scotiabank.com.pe", daysAgo: 2 },
    { url: "http://viabcp-verifica.example-phish.test/clave", level: "critico", score: 97.8, domain: "viabcp-verifica.example-phish.test", daysAgo: 2 },
    { url: "https://scotiabank-online-validacion.com/login", level: "alto", score: 79.5, domain: "scotiabank-online-validacion.com", daysAgo: 1 },
    { url: "https://banbif.com.pe/inicio", level: "seguro_provisional", score: 0.0, domain: "banbif.com.pe", daysAgo: 1 },
    { url: "http://interbank-renovacion.top/validar", level: "critico", score: 95.0, domain: "interbank-renovacion.top", daysAgo: 0 },
    { url: "https://portal-seguridad-banca.net/tokens", level: "medio", score: 48.0, domain: "portal-seguridad-banca.net", daysAgo: 0 },
    { url: "https://viabcp.com/prestamos", level: "seguro_provisional", score: 0.0, domain: "viabcp.com", daysAgo: 0 },
  ];

  sampleItems.forEach((item, idx) => {
    const itemDate = new Date(now.getTime() - item.daysAgo * 86400000 + idx * 1800000);
    const id = `an-seed-${idx + 1000}`;
    const an: Analysis = {
      id,
      created_at: itemDate.toISOString(),
      url: item.url,
      domain: item.domain,
      source_app: "web-ui",
      operation: "link_review",
      correlation_id: `corr-seed-${idx}`,
      level: item.level,
      score: item.score,
      ml_probability: item.level === "critico" ? 0.98 : item.level === "alto" ? 0.85 : 0.02,
      indicators: [
        { code: "rule_eval", points: Math.round(item.score * 0.8), description: `Evaluación de heurísticas para ${item.domain}` }
      ],
      evidence: [
        { source: "reglas", type: "score_trace", detail: `Puntaje inicial ${item.score}/100` }
      ],
      recommendation: item.level === "critico"
        ? "Evidencia sólida de amenaza grave. Bloquear mediante controles autorizados, abrir incidente y notificar."
        : item.level === "alto"
        ? "Evidencia relevante de phishing. Bloquear o exigir confirmación reforzada y escalar a un analista."
        : "Permitir según la política.",
      explanation: `Riesgo ${item.level} (puntaje ${item.score}/100) para el dominio ${item.domain}.`,
      data_incomplete: false,
      engine_version: "1.0.0",
      model_version: "rf-phish-synthetic-v1.0",
      latency_ms: Math.round((2.5 + (idx % 3) * 1.8) * 10) / 10,
      user_id: 1,
    };
    analyses.push(an);

    if (item.level === "alto" || item.level === "critico") {
      const statuses: AlertStatus[] = ["open", "investigating", "confirmed", "resolved"];
      const status = statuses[idx % statuses.length];
      alerts.push({
        id: alertSeq++,
        analysis_id: id,
        level: item.level,
        status,
        assignee_id: 2,
        note: `Alerta generada automáticamente para ${item.domain}`,
        created_at: itemDate.toISOString(),
        updated_at: itemDate.toISOString(),
        domain: item.domain,
        url: item.url,
        score: item.score,
      });
    }
  });

  const auditLogs: AuditLog[] = [
    { id: 1, ts: new Date(now.getTime() - 86400000 * 3).toISOString(), user: "admin@bankshield.local", action: "system_bootstrap", resource: "system", outcome: "ok", ip: "127.0.0.1", detail: "Sistema inicializado con reglas bancarias estándar" },
    { id: 2, ts: new Date(now.getTime() - 86400000 * 2).toISOString(), user: "analyst@bankshield.local", action: "intel_refresh", resource: "feeds", outcome: "ok", ip: "10.0.1.42", detail: "Feeds actualizados: feed-cert-peru (120 indicadores)" },
    { id: 3, ts: new Date(now.getTime() - 86400000 * 1).toISOString(), user: "admin@bankshield.local", action: "login", resource: "auth", outcome: "ok", ip: "192.168.1.10", detail: "Inicio de sesión administrativo exitoso" },
    { id: 4, ts: new Date(now.getTime() - 3600000 * 4).toISOString(), user: "operator@bankshield.local", action: "analyze", resource: "url:bcp-seguro-acceso.example-phish.test", outcome: "ok", ip: "10.0.1.55", detail: "Análisis clasificado como CRÍTICO" },
    { id: 5, ts: new Date(now.getTime() - 1800000).toISOString(), user: "analyst@bankshield.local", action: "alert_update", resource: "alert:1", outcome: "ok", ip: "10.0.1.42", detail: "Estado actualizado a 'investigating'" },
  ];

  return {
    users,
    threatIndicators,
    analyses,
    alerts,
    auditLogs,
    nextAlertId: alertSeq,
    nextAuditId: auditLogs.length + 1,
    nextIndicatorId: threatIndicators.length + 1,
  };
}

class DatabaseService {
  private data: StoredData;

  constructor() {
    this.data = this.load();
  }

  private load(): StoredData {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Fallback
    }
    const initial = getInitialData();
    this.save(initial);
    return initial;
  }

  private save(data: StoredData) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch {
      // localStorage may be restricted or full
    }
  }

  // Session
  getCurrentUser(): User | null {
    try {
      const s = localStorage.getItem(SESSION_KEY);
      if (s) return JSON.parse(s);
    } catch {
      // ignore
    }
    // Default to admin user for immediate seamless experience if none set
    const admin = this.data.users.find((u) => u.email === "admin@bankshield.local") || this.data.users[0];
    return admin;
  }

  setCurrentUser(user: User | null) {
    try {
      if (user) {
        localStorage.setItem(SESSION_KEY, JSON.stringify(user));
      } else {
        localStorage.removeItem(SESSION_KEY);
      }
    } catch {
      // ignore
    }
  }

  // Users
  getUsers(): User[] {
    return [...this.data.users];
  }

  getUserByEmail(email: string): User | undefined {
    return this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  createUser(email: string, fullName: string, role: Role): User {
    const existing = this.getUserByEmail(email);
    if (existing) {
      throw new Error("El correo ya existe");
    }
    const newUser: User = {
      id: this.data.users.length + 1,
      email: email.toLowerCase(),
      full_name: fullName,
      role,
      is_active: true,
      created_at: new Date().toISOString(),
    };
    this.data.users.push(newUser);
    this.save(this.data);
    return newUser;
  }

  setUserActive(userId: number, active: boolean, currentAdminId: number): User {
    if (userId === currentAdminId) {
      throw new Error("No puedes desactivar tu propia cuenta");
    }
    const user = this.data.users.find((u) => u.id === userId);
    if (!user) throw new Error("Usuario no encontrado");
    user.is_active = active;
    this.save(this.data);
    return user;
  }

  // Threat Intel
  lookupThreat(urlNorm: string, host: string): ThreatLookupResult {
    const exact = this.data.threatIndicators.filter((t) => t.url_norm === urlNorm);
    const hostOnly = this.data.threatIndicators.filter((t) => t.host === host && t.url_norm !== urlNorm);
    const hasExternalFeeds = this.data.threatIndicators.some((t) => t.source.startsWith("feed-"));

    return {
      exact,
      host: hostOnly,
      incomplete: !hasExternalFeeds,
    };
  }

  getThreatIndicators(): ThreatIndicator[] {
    return [...this.data.threatIndicators];
  }

  addThreatIndicator(url: string, source: string, kind: string = "phishing"): boolean {
    const trimmed = url.trim();
    if (!trimmed) return false;
    let urlNorm = trimmed;
    let host = "";
    try {
      const u = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
      host = u.hostname;
      urlNorm = `${u.protocol}//${host}${u.pathname}`;
    } catch {
      return false;
    }

    const exists = this.data.threatIndicators.some(
      (t) => t.url_norm === urlNorm && t.source === source
    );
    if (exists) return false;

    const ind: ThreatIndicator = {
      id: this.data.nextIndicatorId++,
      url_norm: urlNorm,
      host,
      source,
      kind,
      added_at: new Date().toISOString(),
    };
    this.data.threatIndicators.push(ind);
    this.save(this.data);
    return true;
  }

  // Analysis & Alerts
  analyzeUrl(rawUrl: string, sourceApp: string = "web-ui", operation: string = "link_review", correlationId: string = ""): Analysis {
    const currentUser = this.getCurrentUser();
    const result = assessUrl(
      rawUrl,
      sourceApp,
      operation,
      correlationId,
      currentUser?.id || null,
      (u, h) => this.lookupThreat(u, h)
    );

    this.data.analyses.unshift(result);

    // If alto or critico, trigger security Alert
    if (result.level === "alto" || result.level === "critico") {
      const alert: Alert = {
        id: this.data.nextAlertId++,
        analysis_id: result.id,
        level: result.level,
        status: "open",
        assignee_id: null,
        note: "",
        created_at: result.created_at,
        updated_at: result.created_at,
        domain: result.domain,
        url: result.url,
        score: result.score,
      };
      this.data.alerts.unshift(alert);
    }

    this.save(this.data);
    this.logAudit("analyze", currentUser?.email || "anonymous", `url:${result.domain}`, "ok", `Nivel ${result.level}, puntaje ${result.score}`);
    return result;
  }

  getAnalyses(): Analysis[] {
    return [...this.data.analyses];
  }

  getAnalysisById(id: string): Analysis | undefined {
    return this.data.analyses.find((a) => a.id === id);
  }

  getAlerts(statusFilter?: string, levelFilter?: string): Alert[] {
    let list = this.data.alerts.map((al) => {
      const an = this.data.analyses.find((a) => a.id === al.analysis_id);
      return {
        ...al,
        domain: an?.domain || al.domain || "desconocido",
        url: an?.url || al.url || "",
        score: an?.score ?? al.score ?? 0,
      };
    });

    if (statusFilter) {
      list = list.filter((a) => a.status === statusFilter);
    }
    if (levelFilter) {
      list = list.filter((a) => a.level === levelFilter);
    }
    return list;
  }

  getAlertById(id: number): { alert: Alert; analysis?: Analysis } | null {
    const al = this.data.alerts.find((a) => a.id === id);
    if (!al) return null;
    const an = this.data.analyses.find((a) => a.id === al.analysis_id);
    return {
      alert: {
        ...al,
        domain: an?.domain || al.domain,
        url: an?.url || al.url,
        score: an?.score ?? al.score,
      },
      analysis: an,
    };
  }

  updateAlert(id: number, patch: { status?: AlertStatus; note?: string; assignee_id?: number | null }): Alert {
    const al = this.data.alerts.find((a) => a.id === id);
    if (!al) throw new Error("Alerta no encontrada");
    if (patch.status) al.status = patch.status;
    if (patch.note !== undefined) al.note = patch.note;
    if (patch.assignee_id !== undefined) al.assignee_id = patch.assignee_id;
    al.updated_at = new Date().toISOString();
    this.save(this.data);

    const currentUser = this.getCurrentUser();
    this.logAudit("alert_update", currentUser?.email || "system", `alert:${id}`, "ok", `Estado=${al.status}`);
    const an = this.data.analyses.find((a) => a.id === al.analysis_id);
    return {
      ...al,
      domain: an?.domain || al.domain,
      url: an?.url || al.url,
      score: an?.score ?? al.score,
    };
  }

  // Audit Logs
  logAudit(action: string, user: string, resource: string, outcome: "ok" | "fail" | "rejected" = "ok", detail: string = "", ip: string = "127.0.0.1") {
    const entry: AuditLog = {
      id: this.data.nextAuditId++,
      ts: new Date().toISOString(),
      user: user || "system",
      action,
      resource,
      outcome,
      ip,
      detail,
    };
    this.data.auditLogs.unshift(entry);
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs.pop();
    }
    this.save(this.data);
  }

  getAuditLogs(limit: number = 200): AuditLog[] {
    return this.data.auditLogs.slice(0, limit);
  }

  // Dashboard summary
  getDashboardSummary(): DashboardSummary {
    const total = this.data.analyses.length;
    const by_level: Record<string, number> = {
      seguro_provisional: 0,
      bajo: 0,
      medio: 0,
      alto: 0,
      critico: 0,
    };
    for (const an of this.data.analyses) {
      by_level[an.level] = (by_level[an.level] || 0) + 1;
    }

    const alerts_by_status: Record<string, number> = {
      open: 0,
      investigating: 0,
      confirmed: 0,
      false_positive: 0,
      resolved: 0,
    };
    for (const al of this.data.alerts) {
      alerts_by_status[al.status] = (alerts_by_status[al.status] || 0) + 1;
    }

    const open_alerts = (alerts_by_status.open || 0) + (alerts_by_status.investigating || 0);

    const now = new Date();
    const per_day: Record<string, number> = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      const key = d.toISOString().slice(0, 10);
      per_day[key] = 0;
    }

    const latencies: number[] = [];
    const sevenDaysAgo = new Date(now.getTime() - 7 * 86400000);

    for (const an of this.data.analyses) {
      const anDate = new Date(an.created_at);
      if (anDate >= sevenDaysAgo) {
        const key = an.created_at.slice(0, 10);
        if (key in per_day) {
          per_day[key] = (per_day[key] || 0) + 1;
        }
        latencies.push(an.latency_ms);
      }
    }

    latencies.sort((a, b) => a - b);
    const avgLatency = latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
    const p95Idx = latencies.length > 0 ? Math.floor(0.95 * (latencies.length - 1)) : 0;
    const p95Latency = latencies.length > 0 ? latencies[p95Idx] : 0;

    return {
      total,
      by_level,
      alerts_by_status,
      open_alerts,
      per_day,
      latency_avg_ms: Math.round(avgLatency * 10) / 10,
      latency_p95_ms: Math.round(p95Latency * 10) / 10,
      model: {
        version: "rf-phish-synthetic-v1.0",
        is_demo: true,
      },
      generated_at: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
    };
  }
}

export const db = new DatabaseService();
