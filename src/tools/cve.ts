/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";

const NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_LIMIT = 5;
const MAX_LIMIT = 20;

/**
 * Best CVSS base score available on a CVE entry, newest metric version
 * first.
 */
function bestScore(
  metrics: Record<string, unknown> | undefined,
): number | null {
  if (!metrics) return null;
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics[key];
    if (Array.isArray(arr) && arr.length > 0) {
      const data = (arr[0] as Record<string, unknown>).cvssData as
        Record<string, unknown> | undefined;
      const score = data?.baseScore;
      if (typeof score === "number") return score;
    }
  }
  return null;
}

function englishDescription(descs: unknown): string {
  if (!Array.isArray(descs)) return "(no description)";
  for (const d of descs) {
    const entry = d as Record<string, unknown>;
    if (entry.lang === "en" && typeof entry.value === "string") {
      return entry.value;
    }
  }
  return "(no description)";
}

/**
 * Look up known vulnerabilities by keyword (product and/or version) via the
 * public NVD API. This queries a public vulnerability database, not the target,
 * so — like DNS resolution — it does not require an approval gate.
 */
export const cveSearch: Tool = {
  name: "cve_search",
  description:
    "Search the NVD database for CVEs matching a keyword (e.g. 'Apache " +
    "2.4.49'). Queries a public vulnerability database, not the target.",
  schema: {
    type: "object",
    properties: {
      keyword: {
        type: "string",
        description: "Product and optional version, e.g. 'OpenSSH 8.2'.",
      },
      limit: {
        type: "integer",
        description:
          `Max results to return (default ${DEFAULT_LIMIT}, ` +
          `max ${MAX_LIMIT}).`,
        minimum: 1,
        maximum: MAX_LIMIT,
      },
    },
    required: ["keyword"],
    additionalProperties: false,
  },

  async run(input) {
    const { keyword, limit } = input;
    if (typeof keyword !== "string" || keyword.trim().length === 0) {
      return { content: "Missing keyword.", isError: true };
    }

    const count = Math.min(
      typeof limit === "number" ? limit : DEFAULT_LIMIT,
      MAX_LIMIT,
    );
    const url = new URL(NVD_ENDPOINT);
    url.searchParams.set("keywordSearch", keyword.trim());
    url.searchParams.set("resultsPerPage", String(count));

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    let payload: unknown;
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (res.status === 403 || res.status === 429) {
        return {
          content: "NVD rate-limited the request. Wait a moment and retry.",
          isError: true,
        };
      }
      if (!res.ok) {
        return { content: `NVD returned HTTP ${res.status}.`, isError: true };
      }
      payload = await res.json();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `CVE lookup failed: ${message}`, isError: true };
    } finally {
      clearTimeout(timeout);
    }

    const vulns = (payload as Record<string, unknown>)?.vulnerabilities;
    if (!Array.isArray(vulns) || vulns.length === 0) {
      return { content: `No CVEs found for "${keyword}".` };
    }

    const rows = vulns
      .map((item) => {
        const cve = (item as Record<string, unknown>).cve as
          Record<string, unknown> | undefined;
        if (!cve) return null;
        const id = typeof cve.id === "string" ? cve.id : "CVE-?";
        const score = bestScore(
          cve.metrics as Record<string, unknown> | undefined,
        );
        const desc = englishDescription(cve.descriptions)
          .replace(/\s+/g, " ")
          .trim();
        const snippet = desc.length > 240 ? `${desc.slice(0, 240)}…` : desc;
        return { id, score, snippet };
      })
      .filter(
        (row): row is { id: string; score: number | null; snippet: string } =>
          row !== null,
      )
      .sort((a, b) => (b.score ?? -1) - (a.score ?? -1));

    const lines = rows.map((row) => {
      const score = row.score !== null ? row.score.toFixed(1) : "n/a";
      return `  ${row.id}  CVSS ${score}\n    ${row.snippet}`;
    });

    return {
      content:
        `CVEs for "${keyword}" (top ${rows.length} by CVSS):\n` +
        lines.join("\n"),
    };
  },
};
