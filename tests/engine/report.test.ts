/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { describe, expect, test } from "bun:test";
import type { Finding, FindingsReport } from "../../src/engine/findings.ts";
import { renderMarkdown, renderPdf } from "../../src/engine/report.ts";

const AT = "2026-07-29T12:00:00.000Z";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "F-1",
    severity: "low",
    target: "target.example",
    title: "Finding",
    description: "A description.",
    createdAt: "2026-07-29T00:00:00.000Z",
    ...over,
  };
}

function report(findings: Finding[]): FindingsReport {
  return {
    version: 1,
    session: "2026-07-29.json",
    createdAt: "2026-07-29T00:00:00.000Z",
    updatedAt: "2026-07-29T00:00:00.000Z",
    findings,
  };
}

describe("renderMarkdown", () => {
  test("orders severities most-severe-first and includes all fields", () => {
    const md = renderMarkdown(
      report([
        finding({ id: "F-1", severity: "low", title: "Low one" }),
        finding({
          id: "F-2",
          severity: "critical",
          title: "Critical one",
          evidence: "GET / 500",
          recommendation: "Patch it",
          references: ["https://example.com/cve"],
        }),
      ]),
      AT,
    );
    expect(md).toContain("# Security findings — 2026-07-29.json");
    expect(md).toContain("2 total (1 critical, 1 low)");
    expect(md).toContain("### F-2 — Critical one");
    expect(md).toContain("**Evidence**");
    expect(md).toContain("GET / 500");
    expect(md).toContain("**Recommendation**");
    expect(md).toContain("- https://example.com/cve");
    // CRITICAL section precedes the LOW section.
    expect(md.indexOf("## CRITICAL")).toBeLessThan(md.indexOf("## LOW"));
  });

  test("handles an empty report", () => {
    const md = renderMarkdown(report([]), AT);
    expect(md).toContain("0 total (none)");
    expect(md).toContain("No findings were recorded");
  });
});

describe("renderPdf", () => {
  test("produces a valid PDF for a populated report", async () => {
    const buf = await renderPdf(
      report([
        finding({ severity: "critical", title: "RCE" }),
        finding({
          id: "F-2",
          title: "Info leak",
          evidence: "Server: nginx/1.0",
          recommendation: "Hide the banner",
          references: ["https://example.com/ref"],
        }),
      ]),
      AT,
    );
    expect(buf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(buf.length).toBeGreaterThan(500);
  });

  test("produces a valid PDF for an empty report", async () => {
    const buf = await renderPdf(report([]), AT);
    expect(buf.subarray(0, 5).toString()).toBe("%PDF-");
  });
});
