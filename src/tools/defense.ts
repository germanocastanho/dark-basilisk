/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { readFile } from "node:fs/promises";
import { Resolver } from "node:dns/promises";
import type { Tool } from "./types.ts";
import { safePath } from "./sandbox.ts";
import { parseHttpUrl, probeRequest } from "./http.ts";

const MAX_FILE_BYTES = 1024 * 1024;

/**
 * Generate a Sigma detection rule from structured input. Turns an observed
 * attacker behavior into a portable YAML rule the blue team can load into a
 * SIEM. Offline formatter — no target contact.
 */
export const sigmaGenerate: Tool = {
  name: "sigma_generate",
  description:
    "Generate a Sigma detection rule (YAML) from a title, log source, and field selection. Offline; use it to turn a finding into a deployable detection.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      title: { type: "string", description: "Short rule title." },
      description: { type: "string", description: "What the rule detects." },
      product: {
        type: "string",
        description: "Log source product, e.g. windows, linux, apache.",
      },
      category: {
        type: "string",
        description: "Log source category, e.g. process_creation, webserver.",
      },
      service: {
        type: "string",
        description: "Log source service, e.g. sshd, security.",
      },
      selection: {
        type: "object",
        description: "Field → value(s) map that defines the match.",
        additionalProperties: true,
      },
      condition: {
        type: "string",
        description: "Sigma condition (default `selection`).",
      },
      level: {
        type: "string",
        enum: ["informational", "low", "medium", "high", "critical"],
        description: "Severity level (default medium).",
      },
    },
    required: ["title", "selection"],
    additionalProperties: false,
  },

  async run(input) {
    const title = typeof input.title === "string" ? input.title : "";
    if (title.trim() === "")
      return { content: "Missing title.", isError: true };
    const selection =
      input.selection && typeof input.selection === "object"
        ? (input.selection as Record<string, unknown>)
        : null;
    if (!selection || Object.keys(selection).length === 0) {
      return { content: "Missing selection fields.", isError: true };
    }

    const logsource: string[] = [];
    if (typeof input.category === "string")
      logsource.push(`    category: ${input.category}`);
    if (typeof input.product === "string")
      logsource.push(`    product: ${input.product}`);
    if (typeof input.service === "string")
      logsource.push(`    service: ${input.service}`);

    const selLines: string[] = [];
    for (const [field, value] of Object.entries(selection)) {
      if (Array.isArray(value)) {
        selLines.push(`        ${field}:`);
        for (const v of value)
          selLines.push(`            - ${JSON.stringify(v)}`);
      } else {
        selLines.push(`        ${field}: ${JSON.stringify(value)}`);
      }
    }

    const level = typeof input.level === "string" ? input.level : "medium";
    const condition =
      typeof input.condition === "string" ? input.condition : "selection";
    const desc =
      typeof input.description === "string" ? input.description : title;

    const yaml = [
      `title: ${title}`,
      "id: 00000000-0000-0000-0000-000000000000",
      "status: experimental",
      `description: ${desc}`,
      "logsource:",
      ...(logsource.length > 0 ? logsource : ["    product: unknown"]),
      "detection:",
      "    selection:",
      ...selLines,
      `    condition: ${condition}`,
      "falsepositives:",
      "    - Unknown",
      `level: ${level}`,
    ].join("\n");

    return { content: `Sigma rule:\n\n${yaml}\n` };
  },
};

/** Attack signatures scanned for in log lines. */
const LOG_SIGNATURES: Array<{ label: string; re: RegExp }> = [
  {
    label: "SQLi",
    re: /(\bunion\b.*\bselect\b|' or '1'='1|sleep\(\d+\)|information_schema)/i,
  },
  { label: "XSS", re: /(<script|onerror=|onload=|javascript:|<svg\/)/i },
  { label: "Path traversal", re: /(\.\.\/|\.\.%2f|\/etc\/passwd|\.\.\\)/i },
  {
    label: "Command injection",
    re: /(;\s*(cat|wget|curl|nc|bash)\b|\$\(|`.*`|\|\s*sh\b)/i,
  },
  { label: "Log4Shell", re: /\$\{jndi:(ldap|rmi|dns):/i },
  {
    label: "Scanner UA",
    re: /(sqlmap|nikto|nmap|masscan|nuclei|acunetix|dirbuster|wpscan)/i,
  },
  {
    label: "Auth failure",
    re: /(failed password|authentication failure|invalid user|401 |403 )/i,
  },
];

/**
 * Triage a local log file for attack indicators: scans each line against a set
 * of attack signatures and summarizes counts with sample lines. Read-only
 * within the working directory, so no approval gate.
 */
export const logTriage: Tool = {
  name: "log_triage",
  description:
    "Scan a local log file for attack signatures (SQLi, XSS, traversal, command injection, Log4Shell, scanners, auth failures) and summarize hits. Confined to the working directory.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Log path relative to the working directory.",
      },
      samples: {
        type: "integer",
        description: "Sample lines to show per signature (default 3).",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },

  async run(input, ctx) {
    const path = typeof input.path === "string" ? input.path : "";
    const target = safePath(ctx.workdir, path);
    if (!target) {
      return { content: "Path escapes the working directory.", isError: true };
    }
    let text: string;
    try {
      const bytes = await readFile(target);
      if (bytes.byteLength > MAX_FILE_BYTES) {
        return {
          content: `File is ${bytes.byteLength} bytes, over the ${MAX_FILE_BYTES}-byte limit.`,
          isError: true,
        };
      }
      text = bytes.toString("utf8");
    } catch (err) {
      return {
        content: `Cannot read file: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    }

    const sampleCap = Number.isInteger(input.samples)
      ? (input.samples as number)
      : 3;
    const lines = text.split("\n");
    const hits = new Map<string, { count: number; samples: string[] }>();
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      for (const sig of LOG_SIGNATURES) {
        if (sig.re.test(line)) {
          const entry = hits.get(sig.label) ?? { count: 0, samples: [] };
          entry.count += 1;
          if (entry.samples.length < sampleCap) {
            entry.samples.push(`      L${i + 1}: ${line.slice(0, 160)}`);
          }
          hits.set(sig.label, entry);
        }
      }
    }

    if (hits.size === 0) {
      return {
        content: `Triaged ${lines.length} lines — no attack signatures.`,
      };
    }
    const blocks = [...hits.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .map(
        ([label, e]) =>
          `  [!] ${label}: ${e.count} hit(s)\n${e.samples.join("\n")}`,
      );
    return {
      content: `Triaged ${lines.length} lines across ${hits.size} signature(s):\n${blocks.join("\n")}`,
    };
  },
};

interface Dep {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
}

/** Parse dependencies out of a package.json or requirements.txt body. */
function parseManifest(name: string, body: string): Dep[] {
  const deps: Dep[] = [];
  if (name.endsWith("package.json")) {
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(body);
    } catch {
      return deps;
    }
    for (const key of ["dependencies", "devDependencies"]) {
      const block = json[key];
      if (block && typeof block === "object") {
        for (const [dep, ver] of Object.entries(
          block as Record<string, string>,
        )) {
          deps.push({
            name: dep,
            version: String(ver).replace(/^[\^~>=<\s]+/, ""),
            ecosystem: "npm",
          });
        }
      }
    }
  } else {
    for (const line of body.split(/\r?\n/)) {
      const m = line.trim().match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9][\w.]*)/);
      if (m) deps.push({ name: m[1]!, version: m[2]!, ecosystem: "PyPI" });
    }
  }
  return deps;
}

/**
 * Audit a local dependency manifest (package.json or requirements.txt) against
 * the public OSV.dev vulnerability database. Queries a public DB, not the
 * target, so — like cve_search — it is not gated.
 */
export const dependencyAudit: Tool = {
  name: "dependency_audit",
  description:
    "Audit a local package.json or requirements.txt against the OSV.dev vulnerability database and report vulnerable dependencies. Queries a public DB, not the target.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description:
          "Manifest path (package.json or requirements.txt), relative to the working directory.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },

  async run(input, ctx) {
    const path = typeof input.path === "string" ? input.path : "";
    const target = safePath(ctx.workdir, path);
    if (!target) {
      return { content: "Path escapes the working directory.", isError: true };
    }
    let body: string;
    try {
      body = (await readFile(target)).toString("utf8");
    } catch (err) {
      return {
        content: `Cannot read manifest: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    }

    const deps = parseManifest(path, body).slice(0, 100);
    if (deps.length === 0) {
      return {
        content: "No pinned dependencies parsed from the manifest.",
        isError: true,
      };
    }

    const queries = deps.map((d) => ({
      package: { name: d.name, ecosystem: d.ecosystem },
      version: d.version,
    }));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    let payload: { results?: Array<{ vulns?: Array<{ id: string }> }> };
    try {
      const res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });
      if (!res.ok) {
        return { content: `OSV returned HTTP ${res.status}.`, isError: true };
      }
      payload = (await res.json()) as typeof payload;
    } catch (err) {
      return {
        content: `OSV lookup failed: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    } finally {
      clearTimeout(timer);
    }

    const results = payload.results ?? [];
    const lines: string[] = [];
    results.forEach((r, i) => {
      const vulns = r?.vulns ?? [];
      if (vulns.length > 0) {
        const dep = deps[i]!;
        lines.push(
          `  [!] ${dep.name}@${dep.version} — ${vulns.map((v) => v.id).join(", ")}`,
        );
      }
    });

    return {
      content:
        `Dependency audit — ${deps.length} packages checked via OSV\n` +
        (lines.length > 0
          ? `${lines.join("\n")}\n${lines.length} vulnerable.`
          : "  No known vulnerabilities."),
    };
  },
};

interface HeaderCheck {
  header: string;
  advice: string;
}

const HARDENING: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    advice: "add HSTS: max-age=63072000; includeSubDomains; preload",
  },
  {
    header: "content-security-policy",
    advice: "add a restrictive CSP (default-src 'self')",
  },
  { header: "x-content-type-options", advice: "add: nosniff" },
  {
    header: "x-frame-options",
    advice: "add: DENY (or frame-ancestors in CSP)",
  },
  {
    header: "referrer-policy",
    advice: "add: no-referrer or strict-origin-when-cross-origin",
  },
  {
    header: "permissions-policy",
    advice: "add a Permissions-Policy limiting powerful features",
  },
];

/**
 * Fetch a URL and produce hardening recommendations for missing or weak
 * security headers. Reaches the target, so it is gated.
 */
export const headerHarden: Tool = {
  name: "header_harden",
  description:
    "Fetch a URL's response headers and recommend fixes for missing/weak security headers (HSTS, CSP, X-Frame-Options, ...). Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute URL to inspect." },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const res = await probeRequest(url, { redirect: "follow" });
    if (res.error) {
      return { content: `Request failed: ${res.error}`, isError: true };
    }

    const missing = HARDENING.filter((h) => !res.headers.has(h.header));
    const present = HARDENING.filter((h) => res.headers.has(h.header)).map(
      (h) => h.header,
    );
    const setCookie = res.headers.get("set-cookie");
    const cookieIssues: string[] = [];
    if (setCookie) {
      if (!/;\s*Secure/i.test(setCookie))
        cookieIssues.push("cookie missing Secure");
      if (!/;\s*HttpOnly/i.test(setCookie))
        cookieIssues.push("cookie missing HttpOnly");
      if (!/;\s*SameSite/i.test(setCookie))
        cookieIssues.push("cookie missing SameSite");
    }

    const lines = [
      ...missing.map((h) => `  [!] ${h.header}: MISSING — ${h.advice}`),
      ...cookieIssues.map((c) => `  [!] ${c}`),
    ];
    return {
      content:
        `Header hardening for ${url.href} (HTTP ${res.status})\n` +
        `  present: ${present.length > 0 ? present.join(", ") : "none"}\n` +
        (lines.length > 0
          ? lines.join("\n")
          : "  All checked headers present."),
    };
  },
};

function classifyIndicator(ioc: string): string {
  if (/^[0-9a-f]{64}$/i.test(ioc)) return "sha256";
  if (/^[0-9a-f]{40}$/i.test(ioc)) return "sha1";
  if (/^[0-9a-f]{32}$/i.test(ioc)) return "md5";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ipv4";
  if (ioc.includes(":") && /^[0-9a-f:]+$/i.test(ioc)) return "ipv6";
  if (/^https?:\/\//i.test(ioc)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ioc)) return "domain";
  return "unknown";
}

/**
 * Classify indicators of compromise and check IPv4s against a public DNS
 * blocklist (Spamhaus ZEN). Only public-infrastructure DNS lookups leave the
 * machine — like dns_lookup, so it is not gated.
 */
export const iocCheck: Tool = {
  name: "ioc_check",
  description:
    "Classify indicators (hashes, IPs, domains, URLs) and check IPv4s against a public DNS blocklist (Spamhaus ZEN). Uses public DNS only, not the target.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      indicators: {
        type: "array",
        items: { type: "string" },
        description: "IOCs to check: IPs, domains, URLs, or file hashes.",
      },
    },
    required: ["indicators"],
    additionalProperties: false,
  },

  async run(input) {
    const iocs = Array.isArray(input.indicators)
      ? input.indicators.map(String).slice(0, 100)
      : [];
    if (iocs.length === 0) {
      return {
        content: "Provide a non-empty indicators array.",
        isError: true,
      };
    }
    const resolver = new Resolver({ timeout: 4000, tries: 1 });

    const lines: string[] = [];
    for (const ioc of iocs) {
      const kind = classifyIndicator(ioc);
      if (kind === "ipv4") {
        const reversed = ioc.split(".").reverse().join(".");
        try {
          await resolver.resolve4(`${reversed}.zen.spamhaus.org`);
          lines.push(`  [!] ${ioc} (ipv4): LISTED on Spamhaus ZEN`);
        } catch {
          lines.push(`  [ ] ${ioc} (ipv4): not listed`);
        }
      } else {
        lines.push(`  [·] ${ioc} (${kind})`);
      }
    }
    return {
      content: `IOC check — ${iocs.length} indicator(s)\n${lines.join("\n")}`,
    };
  },
};
