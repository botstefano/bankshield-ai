export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
]);

export const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work", "support",
  "country", "kim", "loan", "icu", "buzz", "rest", "cyou", "cam", "monster"
]);

export const KEYWORDS = [
  "login", "signin", "verify", "verif", "secure", "account", "update", "confirm", "banking",
  "password", "token", "clave", "validar", "actualiza", "suspend", "bloque", "acceso", "seguro"
];

export const SECOND_LEVEL = new Set(["com", "org", "net", "gob", "edu", "co", "gov", "ac"]);

export const BANK_DOMAINS = [
  "bcp.com.pe",
  "viabcp.com",
  "bbva.pe",
  "interbank.pe",
  "scotiabank.com.pe",
  "banbif.com.pe"
];

const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "5": "s",
  "4": "a",
  "7": "t",
};

export const FEATURE_ORDER = [
  "url_length", "host_length", "num_dots", "num_subdomains", "num_hyphens_host", "digit_ratio_host",
  "has_ip", "has_at", "is_https", "is_shortener", "suspicious_tld", "is_idn", "num_keywords",
  "path_depth", "num_params", "host_entropy", "brand_abuse", "min_brand_distance", "nonstandard_port",
] as const;

export class InvalidUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidUrlError";
  }
}

export class BlockedTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlockedTargetError";
  }
}

export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().split(".");
  if (labels.length >= 3 && SECOND_LEVEL.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2) {
    return labels.slice(-3).join(".");
  }
  return labels.length >= 2 ? labels.slice(-2).join(".") : host;
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost));
    }
    prev = cur;
  }
  return prev[prev.length - 1];
}

export function entropy(s: string): number {
  if (!s) return 0.0;
  const counts: Record<string, number> = {};
  for (const c of s) {
    counts[c] = (counts[c] || 0) + 1;
  }
  const len = s.length;
  let ent = 0;
  for (const c in counts) {
    const p = counts[c] / len;
    ent -= p * Math.log2(p);
  }
  return Math.round(ent * 1000) / 1000;
}

export function isIp(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "");
  // IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = clean.match(ipv4Regex);
  if (match) {
    return match.slice(1).every((num) => {
      const n = parseInt(num, 10);
      return n >= 0 && n <= 255;
    });
  }
  // IPv6
  if (clean.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(clean);
  }
  return false;
}

export function isPrivateHost(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (clean === "localhost" || clean.endsWith(".local") || clean.endsWith(".internal") || clean.endsWith(".localhost") || clean.endsWith(".lan")) {
    return true;
  }
  // IPv4 check
  const parts = clean.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    // 127.0.0.0/8
    if (parts[0] === 127) return true;
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 172.16.0.0/12 (172.16 - 172.31)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 169.254.0.0/16 (link local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0
    if (parts[0] === 0) return true;
  }
  // IPv6 loopback
  if (clean === "::1" || clean === "fe80::" || clean.startsWith("fe80:")) {
    return true;
  }
  return false;
}

export interface NormalizedUrlParts {
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  query: string;
  has_userinfo: boolean;
  normalized: string;
  is_idn: boolean;
  raw_len: number;
  full_lower: string;
}

export function normalizeUrl(raw: string): NormalizedUrlParts {
  const trimmed = (raw || "").trim();
  if (!trimmed || trimmed.length > 2048 || /[\r\n\t ]/.test(trimmed)) {
    throw new InvalidUrlError("URL vacía, demasiado larga o con espacios/saltos de línea.");
  }

  let parseTarget = trimmed;
  if (!parseTarget.includes("://")) {
    parseTarget = "https://" + parseTarget;
  }

  let parsed: URL;
  try {
    parsed = new URL(parseTarget);
  } catch (err) {
    throw new InvalidUrlError(`URL mal formada: ${(err as Error).message}`);
  }

  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    throw new InvalidUrlError(`Esquema no permitido: '${scheme}'. Solo http/https.`);
  }

  let host = (parsed.hostname || "").toLowerCase().replace(/\.+$/, "");
  if (!host) {
    throw new InvalidUrlError("La URL no contiene un host.");
  }

  if (isPrivateHost(host)) {
    throw new BlockedTargetError("Destino interno/privado no permitido (protección SSRF).");
  }

  let is_idn = false;
  // Check for non-ASCII characters or punycode xn--
  if (/[^\u0000-\u007F]/.test(host) || host.startsWith("xn--") || host.includes(".xn--")) {
    is_idn = true;
  }

  const port = parsed.port ? parseInt(parsed.port, 10) : null;
  const path = parsed.pathname || "/";
  const has_userinfo = parseTarget.includes("@");

  // Normalized url without query parameters or fragment to prevent storing sensitive data
  const portStr = port ? `:${port}` : "";
  const normalized = `${scheme}://${host}${portStr}${path}`;

  return {
    scheme,
    host,
    port,
    path,
    query: parsed.search ? parsed.search.slice(1) : "",
    has_userinfo,
    normalized,
    is_idn,
    raw_len: trimmed.length,
    full_lower: trimmed.toLowerCase(),
  };
}

export function brandTokens(): Record<string, string> {
  const result: Record<string, string> = {};
  for (const d of BANK_DOMAINS) {
    const token = d.split(".")[0];
    result[token] = d;
  }
  return result;
}

export function isAuthorizedDomain(host: string): boolean {
  const lower = host.toLowerCase();
  return BANK_DOMAINS.some((d) => lower === d || lower.endsWith("." + d));
}

function translateLeet(text: string): string {
  return text.split("").map((c) => LEET_MAP[c] || c).join("");
}

export interface ExtractedFeatures {
  url_length: number;
  host_length: number;
  num_dots: number;
  num_subdomains: number;
  num_hyphens_host: number;
  digit_ratio_host: number;
  has_ip: number;
  has_at: number;
  is_https: number;
  is_shortener: number;
  suspicious_tld: number;
  is_idn: number;
  num_keywords: number;
  path_depth: number;
  num_params: number;
  host_entropy: number;
  brand_abuse: number;
  min_brand_distance: number;
  nonstandard_port: number;
  _registrable: string;
  _authorized: boolean;
  _lookalike_of: string | null;
  _brand_in_host: string[];
}

export function extractFeatures(p: NormalizedUrlParts): ExtractedFeatures {
  const host = p.host;
  const reg = registrableDomain(host);
  const regLabel = reg.split(".")[0];
  const labels = host.split(".");
  const regPartsCount = reg.split(".").length;
  const numSub = Math.max(0, labels.length - regPartsCount);
  const hostIsIp = isIp(host);
  const tld = labels[labels.length - 1];
  const brands = brandTokens();
  const authorized = isAuthorizedDomain(host);
  const leetLabel = translateLeet(regLabel);

  let min_dist = 10;
  let lookalike_of: string | null = null;

  for (const token in brands) {
    const dom = brands[token];
    if (reg === dom) continue;
    for (const cand of [regLabel, leetLabel]) {
      const d = levenshtein(cand, token);
      if (d < min_dist) {
        min_dist = d;
        const maxThreshold = token.length <= 4 ? 1 : 2;
        if (d <= maxThreshold && token.length >= 3) {
          lookalike_of = dom;
        }
      }
    }
  }

  const cleanHost = host.replace(/-/g, "");
  const brand_in_host = Object.keys(brands).filter(
    (t) => cleanHost.includes(t) && !authorized
  );

  let keywordsCount = 0;
  for (const k of KEYWORDS) {
    if (p.full_lower.includes(k)) {
      keywordsCount++;
    }
  }

  const digitCount = (host.match(/\d/g) || []).length;
  const digit_ratio_host = digitCount / Math.max(1, host.length);

  const pathSegments = p.path.split("/").filter(Boolean);
  const queryParams = p.query ? p.query.split("&").filter(Boolean) : [];

  return {
    url_length: p.normalized.length,
    host_length: host.length,
    num_dots: (host.match(/\./g) || []).length,
    num_subdomains: numSub,
    num_hyphens_host: (host.match(/-/g) || []).length,
    digit_ratio_host,
    has_ip: hostIsIp ? 1 : 0,
    has_at: p.has_userinfo ? 1 : 0,
    is_https: p.scheme === "https" ? 1 : 0,
    is_shortener: SHORTENERS.has(reg) ? 1 : 0,
    suspicious_tld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    is_idn: p.is_idn ? 1 : 0,
    num_keywords: keywordsCount,
    path_depth: pathSegments.length,
    num_params: queryParams.length,
    host_entropy: entropy(host),
    brand_abuse: brand_in_host.length > 0 ? 1 : 0,
    min_brand_distance: authorized ? 10 : min_dist,
    nonstandard_port: p.port !== null && p.port !== 80 && p.port !== 443 ? 1 : 0,
    _registrable: reg,
    _authorized: authorized,
    _lookalike_of: lookalike_of,
    _brand_in_host: brand_in_host,
  };
}

export function featureVector(f: ExtractedFeatures): number[] {
  return [
    f.url_length,
    f.host_length,
    f.num_dots,
    f.num_subdomains,
    f.num_hyphens_host,
    f.digit_ratio_host,
    f.has_ip,
    f.has_at,
    f.is_https,
    f.is_shortener,
    f.suspicious_tld,
    f.is_idn,
    f.num_keywords,
    f.path_depth,
    f.num_params,
    f.host_entropy,
    f.brand_abuse,
    f.min_brand_distance,
    f.nonstandard_port,
  ];
}
