import { db } from "./database";
import { LEVEL_ES } from "./explainer";

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

export function exportReport(format: "pdf" | "xlsx" | "docx") {
  const summary = db.getDashboardSummary();
  const alerts = db.getAlerts().slice(0, 100);
  const user = db.getCurrentUser()?.email || "usuario";
  db.logAudit("report_download", user, `format:${format}`, "ok", `Reporte descargado en formato ${format.toUpperCase()}`);

  if (format === "xlsx") {
    // Generate an Excel XML 2003 / CSV spreadsheet with proper UTF-8 BOM
    let csv = "\uFEFF"; // UTF-8 BOM for Excel
    csv += "BankShield AI - Reporte de Seguridad Bancaria\n";
    csv += `Generado el,${summary.generated_at}\n\n`;
    csv += "RESUMEN EJECUTIVO\n";
    csv += `Total de URLs analizadas,${summary.total}\n`;
    csv += `Alertas abiertas,${summary.open_alerts}\n`;
    csv += `Latencia promedio (ms),${summary.latency_avg_ms}\n`;
    csv += `Latencia p95 (ms),${summary.latency_p95_ms}\n\n`;

    csv += "DISTRIBUCIÓN POR NIVEL DE RIESGO\n";
    csv += "Nivel,Cantidad\n";
    for (const [lvl, count] of Object.entries(summary.by_level)) {
      csv += `"${LEVEL_ES[lvl] || lvl}",${count}\n`;
    }
    csv += "\n";

    csv += "CENTRO DE ALERTAS RECIENTES\n";
    csv += "Fecha (UTC),Dominio,Nivel,Puntaje,Estado,URL Original\n";
    for (const a of alerts) {
      csv += `"${a.created_at.slice(0, 19).replace("T", " ")}","${a.domain || ""}","${LEVEL_ES[a.level] || a.level}",${a.score},"${a.status}","${a.url || ""}"\n`;
    }

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    triggerDownload(blob, "bankshield-reporte.csv");
    return;
  }

  if (format === "docx") {
    // Generate a Word-compatible HTML document with Word namespace
    const wordHtml = `
      <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
      <head>
        <meta charset='utf-8'>
        <title>BankShield AI - Informe Técnico</title>
        <style>
          body { font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #14212b; }
          h1 { color: #12304a; font-size: 22pt; margin-bottom: 4px; }
          h2 { color: #0f766e; font-size: 14pt; margin-top: 18px; border-bottom: 1px solid #d5dddb; padding-bottom: 4px; }
          p { font-size: 10pt; line-height: 1.5; margin: 4px 0; }
          table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 9pt; }
          th { background: #12304a; color: #ffffff; padding: 6px 8px; text-align: left; }
          td { padding: 6px 8px; border-bottom: 1px solid #d5dddb; }
          .muted { color: #5b6b73; font-size: 8.5pt; }
          .badge { padding: 2px 6px; font-weight: bold; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h1>BankShield AI - Informe Técnico</h1>
        <p class='muted'>Generado: ${summary.generated_at}</p>
        <p><strong>Métricas globales:</strong> Total URLs analizadas: ${summary.total} &nbsp;|&nbsp; Alertas activas: ${summary.open_alerts} &nbsp;|&nbsp; Latencia media: ${summary.latency_avg_ms} ms &nbsp;|&nbsp; Latencia p95: ${summary.latency_p95_ms} ms</p>
        
        <h2>Distribución por Nivel de Riesgo</h2>
        <table>
          <thead><tr><th>Nivel</th><th>Cantidad</th></tr></thead>
          <tbody>
            ${Object.entries(summary.by_level).map(([k, v]) => `<tr><td>${LEVEL_ES[k] || k}</td><td>${v}</td></tr>`).join("")}
          </tbody>
        </table>

        <h2>Alertas de Seguridad Recientes</h2>
        <table>
          <thead>
            <tr><th>Fecha (UTC)</th><th>Dominio</th><th>Nivel</th><th>Puntaje</th><th>Estado</th></tr>
          </thead>
          <tbody>
            ${alerts.slice(0, 40).map((a) => `
              <tr>
                <td>${a.created_at.slice(0, 19).replace("T", " ")}</td>
                <td>${a.domain || ""}</td>
                <td>${LEVEL_ES[a.level] || a.level}</td>
                <td>${a.score}</td>
                <td>${a.status}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
        <p class='muted' style='margin-top: 18px;'><em>Nota técnica: una disminución de alertas no implica por sí sola mayor seguridad; puede indicar menor capacidad de detección o degradación de fuentes externas.</em></p>
      </body>
      </html>
    `;
    const blob = new Blob([wordHtml], { type: "application/msword;charset=utf-8" });
    triggerDownload(blob, "bankshield-reporte.doc");
    return;
  }

  if (format === "pdf") {
    // Generate printable HTML window / preview or printable report for PDF saving
    const printWindow = window.open("", "_blank");
    if (!printWindow) {
      alert("Por favor habilita las ventanas emergentes para generar el reporte PDF.");
      return;
    }
    printWindow.document.write(`
      <!doctype html>
      <html>
      <head>
        <title>BankShield AI - Reporte Ejecutivo</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 30px; color: #14212b; }
          .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #12304a; padding-bottom: 12px; margin-bottom: 20px; }
          h1 { margin: 0; color: #12304a; font-size: 24px; }
          .meta { color: #5b6b73; font-size: 13px; }
          .kpi-row { display: flex; gap: 20px; margin-bottom: 24px; }
          .kpi-box { flex: 1; background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 16px; border-radius: 6px; }
          .kpi-box b { display: block; font-size: 22px; color: #12304a; }
          .kpi-box span { font-size: 12px; color: #64748b; }
          table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
          th { background: #12304a; color: #fff; padding: 8px 10px; text-align: left; }
          td { padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }
          .badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; color: white; display: inline-block; }
          .critico { background: #9f1239; }
          .alto { background: #c2410c; }
          .medio { background: #c27a12; }
          .bajo { background: #8a8f2a; }
          .seguro { background: #2f7d4f; }
          .footer { margin-top: 30px; font-size: 11px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px; }
          @media print {
            .no-print { display: none; }
          }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <h1>BankShield AI</h1>
            <div class="meta">Reporte Ejecutivo de Detección de Phishing Bancario</div>
          </div>
          <div class="meta" style="text-align: right;">
            <div>Generado: ${summary.generated_at}</div>
            <div>Modelo: ${summary.model.version}</div>
          </div>
        </div>

        <div class="kpi-row">
          <div class="kpi-box"><b>${summary.total}</b><span>URLs analizadas</span></div>
          <div class="kpi-box"><b>${summary.open_alerts}</b><span>Alertas pendientes</span></div>
          <div class="kpi-box"><b>${summary.latency_avg_ms} ms</b><span>Latencia media</span></div>
          <div class="kpi-box"><b>${summary.latency_p95_ms} ms</b><span>Latencia p95 (7d)</span></div>
        </div>

        <h3 style="margin-top: 24px; color: #12304a;">Distribución de Amenazas por Nivel</h3>
        <table>
          <thead><tr><th>Nivel</th><th>Cantidad de Incidentes</th></tr></thead>
          <tbody>
            ${Object.entries(summary.by_level).map(([k, v]) => `
              <tr>
                <td><strong>${LEVEL_ES[k] || k}</strong></td>
                <td>${v}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>

        <h3 style="margin-top: 24px; color: #12304a;">Alertas de Seguridad Recientes</h3>
        <table>
          <thead>
            <tr><th>Fecha</th><th>Dominio</th><th>Nivel</th><th>Puntaje</th><th>Estado</th></tr>
          </thead>
          <tbody>
            ${alerts.slice(0, 30).map((a) => {
              const badgeClass = a.level.startsWith("seguro") ? "seguro" : a.level;
              return `
                <tr>
                  <td>${a.created_at.slice(0, 19).replace("T", " ")}</td>
                  <td><strong>${a.domain || ""}</strong></td>
                  <td><span class="badge ${badgeClass}">${LEVEL_ES[a.level] || a.level}</span></td>
                  <td>${a.score}/100</td>
                  <td>${a.status}</td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>

        <div class="footer">
          Nota: una disminución de alertas no implica por sí sola mayor seguridad; puede indicar pérdida de capacidad de detección.
          Documento generado automáticamente por BankShield AI.
        </div>

        <div class="no-print" style="margin-top: 20px; text-align: center;">
          <button onclick="window.print()" style="padding: 10px 20px; font-size: 14px; background: #12304a; color: white; border: none; border-radius: 6px; cursor: pointer;">
            Imprimir o Guardar como PDF
          </button>
        </div>
      </body>
      </html>
    `);
    printWindow.document.close();
  }
}
