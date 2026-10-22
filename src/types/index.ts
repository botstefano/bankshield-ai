export type Role = "admin" | "analyst" | "operator" | "auditor" | "manager";

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface Indicator {
  code: string;
  points: number;
  description: string;
}

export interface Evidence {
  source: string;
  type: string;
  detail: string;
  model_version?: string;
  listed_at?: string;
}

export type RiskLevel = "seguro_provisional" | "bajo" | "medio" | "alto" | "critico" | "desconocido";

export interface Analysis {
  id: string;
  created_at: string;
  url: string;
  domain: string;
  source_app: string;
  operation: string;
  correlation_id: string;
  level: RiskLevel;
  score: number;
  ml_probability: number | null;
  indicators: Indicator[];
  evidence: Evidence[];
  recommendation: string;
  explanation: string;
  data_incomplete: boolean;
  engine_version: string;
  model_version: string;
  latency_ms: number;
  user_id: number | null;
}

export type AlertStatus = "open" | "investigating" | "confirmed" | "false_positive" | "resolved";

export interface Alert {
  id: number;
  analysis_id: string;
  level: RiskLevel;
  status: AlertStatus;
  assignee_id: number | null;
  note: string;
  created_at: string;
  updated_at: string;
  domain?: string;
  url?: string;
  score?: number;
}

export interface AuditLog {
  id: number;
  ts: string;
  user: string;
  action: string;
  resource: string;
  outcome: "ok" | "fail" | "rejected";
  ip: string;
  detail: string;
}

export interface ThreatIndicator {
  id: number;
  url_norm: string;
  host: string;
  source: string;
  kind: string;
  added_at: string;
}

export interface DashboardSummary {
  total: number;
  by_level: Record<string, number>;
  alerts_by_status: Record<string, number>;
  open_alerts: number;
  per_day: Record<string, number>;
  latency_avg_ms: number;
  latency_p95_ms: number;
  model: {
    version: string;
    is_demo: boolean;
  };
  generated_at: string;
}
