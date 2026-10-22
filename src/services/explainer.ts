export const LEVEL_ES: Record<string, string> = {
  seguro_provisional: "Seguro provisional",
  bajo: "Bajo",
  medio: "Medio",
  alto: "Alto",
  critico: "Crítico",
  desconocido: "Desconocido",
};

export function explain(result: {
  level: string;
  score: number;
  domain: string;
  indicators: { description: string }[];
  evidence: { type: string; source: string }[];
  data_incomplete: boolean;
  recommendation: string;
}): string {
  const lines: string[] = [
    `Riesgo ${LEVEL_ES[result.level] || result.level} (puntaje ${result.score}/100) para el dominio ${result.domain}.`
  ];
  if (result.indicators && result.indicators.length > 0) {
    lines.push("Se detectó: " + result.indicators.slice(0, 6).map((i) => i.description).join("; "));
  }
  const confirmed = result.evidence.filter((e) => e.type === "confirmed_match");
  if (confirmed.length > 0) {
    const sources = Array.from(new Set(confirmed.map((e) => e.source))).sort().join(", ");
    lines.push(`Está listada en fuentes de amenazas: ${sources}.`);
  }
  if (result.data_incomplete) {
    lines.push("Atención: la evaluación se hizo con datos de inteligencia incompletos o desactualizados.");
  }
  lines.push(result.recommendation);
  return lines.join(" ");
}
