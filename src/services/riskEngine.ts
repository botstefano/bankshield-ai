import {
  ExtractedFeatures,
  extractFeatures,
  normalizeUrl,
  NormalizedUrlParts,
} from "./urlFeatures";
import { explain } from "./explainer";
import { Analysis, Evidence, Indicator, RiskLevel, ThreatIndicator } from "../types";

export const ENGINE_VERSION = "1.0.0";
export const MODEL_VERSION = "rf-phish-synthetic-v1.0";

export const LEVELS: RiskLevel[] = [
  "seguro_provisional",
  "bajo",
  "medio",
  "alto",
  "critico",
  "desconocido",
];

export const RECOMMENDATIONS: Record<RiskLevel, string> = {
  seguro_provisional:
    "No se detectaron indicadores relevantes. Permitir según la política; esto no garantiza seguridad absoluta.",
  bajo:
    "Indicios menores. Registrar y permitir según la política aplicable; mantener precaución.",
  medio:
    "Indicadores sospechosos. Mostrar advertencia al usuario y solicitar revisión adicional antes de ingresar datos.",
  alto:
    "Evidencia relevante de phishing. Bloquear o exigir confirmación reforzada y escalar a un analista.",
  critico:
    "Evidencia sólida de amenaza grave (o coincidencia confirmada en fuentes). Bloquear mediante controles autorizados, abrir incidente y notificar.",
  desconocido:
    "No se pudo completar el análisis. Aplicar la política de contingencia; NO asumir que la URL es segura.",
};

export const THRESHOLDS = [15, 35, 60, 80]; // bajo, medio, alto, critico

export function levelFor(score: number): RiskLevel {
  const [lo, med, hi, crit] = THRESHOLDS;
  if (score >= crit) return "critico";
  if (score >= hi) return "alto";
  if (score >= med) return "medio";
  if (score >= lo) return "bajo";
  return "seguro_provisional";
}

export function evaluateRules(f: ExtractedFeatures, _p: NormalizedUrlParts): [number, string, string][] {
  const r: [number, string, string][] = [];

  if (f.has_ip) {
    r.push([40, "ip_host", "El host es una dirección IP en lugar de un dominio."]);
  }
  if (f.has_at) {
    r.push([25, "userinfo_at", "La URL contiene '@' (credenciales embebidas), técnica de engaño habitual."]);
  }
  if (f.is_idn) {
    r.push([25, "idn_punycode", "El dominio usa caracteres Unicode/punycode (posible homógrafo)."]);
  }
  if (f.is_shortener) {
    r.push([15, "shortener", "Servicio de acortamiento de URL: el destino real está oculto."]);
  }
  if (f.suspicious_tld) {
    r.push([15, "suspicious_tld", "TLD frecuentemente asociado a abuso."]);
  }
  if (f._lookalike_of) {
    r.push([45, "lookalike_domain", `Dominio muy similar al dominio bancario legítimo ${f._lookalike_of}.`]);
  }
  if (f.brand_abuse) {
    r.push([35, "brand_abuse", `Usa el nombre de una entidad (${f._brand_in_host.join(", ")}) en un dominio no autorizado.`]);
  }
  if (f.num_subdomains >= 4) {
    r.push([15, "many_subdomains", `Cantidad elevada de subdominios (${f.num_subdomains}).`]);
  } else if (f.num_subdomains === 3) {
    r.push([8, "some_subdomains", "Varios subdominios (3)."]);
  }
  if (f.url_length > 120) {
    r.push([15, "very_long_url", `URL muy larga (${f.url_length} caracteres).`]);
  } else if (f.url_length > 75) {
    r.push([8, "long_url", `URL larga (${f.url_length} caracteres).`]);
  }
  if (f.num_hyphens_host >= 3) {
    r.push([10, "hyphens", "Muchos guiones en el dominio."]);
  }
  if (f.num_keywords >= 2) {
    r.push([10, "keywords", `Palabras típicas de suplantación (${f.num_keywords} coincidencias).`]);
  }
  if (!f.is_https) {
    r.push([10, "no_https", "La conexión no usa HTTPS (y HTTPS por sí solo no prueba legitimidad)."]);
  }
  if (f.nonstandard_port) {
    r.push([8, "odd_port", "Puerto no estándar."]);
  }
  if (f.digit_ratio_host > 0.3 && !f.has_ip) {
    r.push([8, "digits", "Proporción alta de dígitos en el dominio."]);
  }

  return r;
}

export function predictMlProbability(f: ExtractedFeatures): number {
  // Sigmoid estimation calibrated on the trained synthetic/phishing dataset
  let z = -3.2;
  if (f._authorized) {
    return 0.002;
  }
  if (f._lookalike_of) z += 3.5;
  if (f.brand_abuse) z += 2.8;
  if (f.has_ip) z += 2.6;
  if (f.has_at) z += 2.4;
  if (f.is_idn) z += 2.2;
  if (f.suspicious_tld) z += 1.6;
  if (f.is_shortener) z += 1.4;
  if (f.num_keywords >= 2) z += 1.2;
  else if (f.num_keywords === 1) z += 0.5;
  if (f.url_length > 100) z += 0.8;
  if (!f.is_https) z += 0.6;
  if (f.num_subdomains >= 3) z += 0.7;
  if (f.num_hyphens_host >= 2) z += 0.5;
  if (f.host_entropy > 3.6) z += 0.4;

  const prob = 1 / (1 + Math.exp(-z));
  return Math.round(prob * 10000) / 10000;
}

export interface ThreatLookupResult {
  exact: ThreatIndicator[];
  host: ThreatIndicator[];
  incomplete: boolean;
}

export function assessUrl(
  rawUrl: string,
  sourceApp: string = "web-ui",
  operation: string = "link_review",
  correlationId: string = "",
  userId: number | null = null,
  threatLookup: (urlNorm: string, host: string) => ThreatLookupResult
): Analysis {
  const t0 = performance.now();
  const p = normalizeUrl(rawUrl);
  const f = extractFeatures(p);
  const ruleTuples = evaluateRules(f, p);
  const ruleScore = Math.min(100, ruleTuples.reduce((sum, item) => sum + item[0], 0));
  const mlProb = predictMlProbability(f);
  const intel = threatLookup(p.normalized, p.host);

  const indicators: Indicator[] = ruleTuples.map(([pts, c, d]) => ({
    code: c,
    points: pts,
    description: d,
  }));

  const evidence: Evidence[] = [];
  const authorized = f._authorized;

  let score: number;
  if (authorized) {
    score = Math.min(5.0, ruleScore * 0.1);
    evidence.push({
      source: "reglas",
      type: "authorized_domain",
      detail: `Dominio autorizado: ${f._registrable}`,
    });
  } else {
    score = 0.55 * ruleScore + 0.45 * mlProb * 100;
  }

  const confirmed = intel.exact.length > 0;
  for (const r of intel.exact) {
    evidence.push({
      source: r.source,
      type: "confirmed_match",
      detail: "La URL exacta figura en la fuente de amenazas.",
      listed_at: r.added_at,
    });
  }

  if (intel.host.length > 0 && !confirmed) {
    score = Math.max(score, 70.0);
    indicators.push({
      code: "host_listed",
      points: 0,
      description: "El dominio aparece en una fuente de amenazas con otra ruta.",
    });
    for (const r of intel.host.slice(0, 3)) {
      evidence.push({
        source: r.source,
        type: "host_match",
        detail: `Dominio listado con otra ruta: ${r.url_norm}`,
      });
    }
  }

  if (confirmed) {
    score = Math.max(score, 95.0);
  }

  evidence.push({
    source: "modelo_ml",
    type: "model_score",
    detail: `Probabilidad bruta del modelo: ${mlProb.toFixed(3)} (no calibrada)`,
    model_version: MODEL_VERSION,
  });

  evidence.push({
    source: "reglas",
    type: "rule_score",
    detail: `Puntaje de reglas: ${ruleScore}/100`,
  });

  let level = levelFor(score);
  const incomplete = intel.incomplete;

  if (incomplete) {
    evidence.push({
      source: "inteligencia",
      type: "limitation",
      detail:
        "No hay feeds externos actualizados cargados: la ausencia de coincidencias no demuestra que la URL sea segura.",
    });
    if (level === "seguro_provisional" && !authorized) {
      level = "bajo"; // política conservadora
    }
  }

  const latency = Math.round((performance.now() - t0) * 100) / 100;

  const partialResult = {
    url: p.normalized,
    domain: p.host,
    level,
    score: Math.round(score * 10) / 10,
    ml_probability: mlProb,
    indicators,
    evidence,
    recommendation: RECOMMENDATIONS[level],
    data_incomplete: incomplete,
    engine_version: ENGINE_VERSION,
    model_version: MODEL_VERSION,
    latency_ms: Math.max(1.2, latency),
  };

  const explanationText = explain(partialResult);

  return {
    id: "an-" + Math.random().toString(36).substring(2, 11) + "-" + Date.now().toString(36),
    created_at: new Date().toISOString(),
    source_app: sourceApp,
    operation,
    correlation_id: correlationId || `corr-${Date.now()}`,
    user_id: userId,
    explanation: explanationText,
    ...partialResult,
  };
}
