/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import PDFDocument from "pdfkit";
import {
  SEVERITIES,
  type Finding,
  type FindingsReport,
  type Severity,
} from "./findings.ts";

export type ReportFormat = "md" | "pdf";

/** Heading colour per severity, weighted by impact. */
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#b00020",
  high: "#b00020",
  medium: "#b26a00",
  low: "#0060a8",
  info: "#666666",
};

/** Severities present in the report, most severe first, with their findings. */
function groupBySeverity(findings: Finding[]): [Severity, Finding[]][] {
  return [...SEVERITIES]
    .reverse()
    .map((severity): [Severity, Finding[]] => [
      severity,
      findings.filter((f) => f.severity === severity),
    ])
    .filter(([, group]) => group.length > 0);
}

/** "2 critical, 1 high" — counts in descending severity, omitting empties. */
function summarize(findings: Finding[]): string {
  const parts = groupBySeverity(findings).map(
    ([severity, group]) => `${group.length} ${severity}`,
  );
  return parts.length > 0 ? parts.join(", ") : "none";
}

/** Render the findings report as a deliverable Markdown document. */
export function renderMarkdown(
  report: FindingsReport,
  generatedAt: string,
): string {
  const lines: string[] = [];
  lines.push(`# Security findings — ${report.session}`, "");
  lines.push(
    `Generated ${generatedAt} · ${report.findings.length} total ` +
      `(${summarize(report.findings)}).`,
    "",
  );

  if (report.findings.length === 0) {
    lines.push("No findings were recorded for this session.", "");
    return lines.join("\n");
  }

  for (const [severity, group] of groupBySeverity(report.findings)) {
    lines.push(`## ${severity.toUpperCase()} (${group.length})`, "");
    for (const f of group) {
      lines.push(`### ${f.id} — ${f.title}`, "");
      lines.push(`- **Target:** ${f.target}`);
      lines.push(`- **Severity:** ${f.severity}`, "");
      lines.push(f.description, "");
      if (f.evidence)
        lines.push("**Evidence**", "", "```", f.evidence, "```", "");
      if (f.recommendation)
        lines.push("**Recommendation**", "", f.recommendation, "");
      if (f.references?.length) {
        lines.push("**References**", "");
        for (const ref of f.references) lines.push(`- ${ref}`);
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}

/**
 * Render the findings report as a PDF, resolving to the document bytes. Text
 * flow and pagination are left to pdfkit; the built-in standard fonts keep the
 * output self-contained (no external font files or converter binaries).
 */
export function renderPdf(
  report: FindingsReport,
  generatedAt: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 56 });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc
      .font("Helvetica-Bold")
      .fontSize(20)
      .fillColor("black")
      .text(`Security findings — ${report.session}`);
    doc.moveDown(0.3);
    doc
      .font("Helvetica")
      .fontSize(10)
      .fillColor("#666666")
      .text(
        `Generated ${generatedAt} · ${report.findings.length} total ` +
          `(${summarize(report.findings)}).`,
      );
    doc.fillColor("black").moveDown();

    if (report.findings.length === 0) {
      doc
        .font("Helvetica")
        .fontSize(12)
        .text("No findings were recorded for this session.");
    } else {
      for (const [severity, group] of groupBySeverity(report.findings)) {
        doc.moveDown(0.6);
        doc
          .font("Helvetica-Bold")
          .fontSize(14)
          .fillColor(SEVERITY_COLOR[severity])
          .text(`${severity.toUpperCase()} (${group.length})`);
        doc.fillColor("black");
        for (const f of group) {
          doc.moveDown(0.4);
          doc.font("Helvetica-Bold").fontSize(12).text(`${f.id} — ${f.title}`);
          doc
            .font("Helvetica")
            .fontSize(9)
            .fillColor("#555555")
            .text(`Target: ${f.target} · Severity: ${f.severity}`);
          doc
            .fillColor("black")
            .font("Helvetica")
            .fontSize(10)
            .text(f.description);
          if (f.evidence) {
            doc
              .moveDown(0.2)
              .font("Helvetica-Bold")
              .fontSize(9)
              .text("Evidence");
            doc.font("Courier").fontSize(9).text(f.evidence);
          }
          if (f.recommendation) {
            doc
              .moveDown(0.2)
              .font("Helvetica-Bold")
              .fontSize(9)
              .text("Recommendation");
            doc.font("Helvetica").fontSize(10).text(f.recommendation);
          }
          if (f.references?.length) {
            doc
              .moveDown(0.2)
              .font("Helvetica-Bold")
              .fontSize(9)
              .text("References");
            doc.font("Helvetica").fontSize(9);
            for (const ref of f.references) doc.text(`• ${ref}`);
          }
        }
      }
    }

    doc.end();
  });
}
