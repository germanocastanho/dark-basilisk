/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import { parseHttpUrl, probeRequest } from "./http.ts";

/** Query parameters to test: an explicit one, or every param on the URL. */
function targetParams(url: URL, param: unknown): string[] {
  if (typeof param === "string" && param.trim() !== "") return [param];
  return [...url.searchParams.keys()];
}

/** Clone `url` with `name` set to `value`. */
function withParam(url: URL, name: string, value: string): URL {
  const next = new URL(url.href);
  next.searchParams.set(name, value);
  return next;
}

/** SQL error signatures that betray an unsanitized query. */
const SQL_ERRORS = [
  /SQL syntax.*MySQL/i,
  /Warning.*\bmysqli?_/i,
  /valid MySQL result/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLite\/JDBCDriver/i,
  /SQLite3::/i,
  /Unclosed quotation mark/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /supplied argument is not a valid/i,
];

/**
 * Heuristic SQL-injection probe. Sends boundary, boolean, and error payloads to
 * a query parameter and looks for SQL error strings, boolean-response
 * divergence, or a time delay. Flags indicators — confirm before reporting.
 */
export const sqliProbe: Tool = {
  name: "sqli_probe",
  description:
    "Heuristic SQL-injection probe on a URL query parameter: checks " +
    "error-based, boolean-based, and time-based signals. Active " +
    "against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "Absolute URL including the query string to test.",
      },
      param: {
        type: "string",
        description: "Parameter to inject. Defaults to every query parameter.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const params = targetParams(url, input.param);
    if (params.length === 0) {
      return {
        content: "No query parameters to test. Provide a URL with a query.",
        isError: true,
      };
    }

    const lines: string[] = [];
    for (const name of params) {
      const base = await probeRequest(withParam(url, name, "1"));
      const errPayload = await probeRequest(withParam(url, name, "1'\""));
      const truthy = await probeRequest(withParam(url, name, "1' OR '1'='1"));
      const falsy = await probeRequest(withParam(url, name, "1' AND '1'='2"));
      const timed = await probeRequest(
        withParam(url, name, "1' OR SLEEP(5)-- -"),
        { timeoutMs: 12000 },
      );

      const signals: string[] = [];
      if (SQL_ERRORS.some((re) => re.test(errPayload.body))) {
        signals.push("error-based (SQL error string reflected)");
      }
      if (
        truthy.status === base.status &&
        Math.abs(truthy.body.length - falsy.body.length) > 32
      ) {
        signals.push(
          `boolean-based (true=${truthy.body.length}b vs ` +
            `false=${falsy.body.length}b)`,
        );
      }
      if (
        timed.error === undefined &&
        timed.elapsedMs - base.elapsedMs > 4000
      ) {
        signals.push(`time-based (+${timed.elapsedMs - base.elapsedMs}ms)`);
      }

      lines.push(
        signals.length > 0
          ? `  [!] ${name}: ${signals.join("; ")}`
          : `  [ ] ${name}: no clear signal`,
      );
    }

    const hit = lines.some((l) => l.startsWith("  [!]"));
    return {
      content:
        `SQLi probe on ${url.href}\n${lines.join("\n")}\n` +
        (hit
          ? "Indicators found — verify manually before recording a finding."
          : "No injection indicators."),
    };
  },
};

/**
 * Reflected-XSS probe. Injects a unique marker with breaking characters and
 * reports whether it is reflected raw (dangerous) or encoded (likely safe).
 */
export const xssProbe: Tool = {
  name: "xss_probe",
  description:
    "Reflected-XSS probe on a URL query parameter: injects a unique " +
    "marker and reports whether special characters reflect unencoded. " +
    "Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute URL with a query string." },
      param: {
        type: "string",
        description: "Parameter to inject. Defaults to every query parameter.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const params = targetParams(url, input.param);
    if (params.length === 0) {
      return { content: "No query parameters to test.", isError: true };
    }

    const marker = `bx${Math.random().toString(36).slice(2, 8)}`;
    const payload = `'"><svg/onload=${marker}>`;
    const lines: string[] = [];
    for (const name of params) {
      const res = await probeRequest(withParam(url, name, payload));
      if (res.error) {
        lines.push(`  [ ] ${name}: request failed (${res.error})`);
        continue;
      }
      const raw =
        res.body.includes(payload) ||
        res.body.includes(`<svg/onload=${marker}>`);
      const encoded = res.body.includes(`&lt;svg`) && res.body.includes(marker);
      if (raw) lines.push(`  [!] ${name}: reflected UNENCODED — likely XSS`);
      else if (encoded) lines.push(`  [ ] ${name}: reflected but encoded`);
      else if (res.body.includes(marker))
        lines.push(`  [~] ${name}: marker reflected, chars stripped/filtered`);
      else lines.push(`  [ ] ${name}: no reflection`);
    }

    const hit = lines.some((l) => l.startsWith("  [!]"));
    return {
      content:
        `XSS probe on ${url.href}\n${lines.join("\n")}\n` +
        (hit
          ? "Unencoded reflection — verify exploitability."
          : "No unencoded reflection."),
    };
  },
};

/**
 * Open-redirect probe. Injects an external URL into a parameter and checks for
 * a 3xx Location (or meta/JS redirect) pointing off-site.
 */
export const openRedirectProbe: Tool = {
  name: "open_redirect_probe",
  description:
    "Open-redirect probe: injects an off-site URL into a parameter and " +
    "checks whether the target redirects to it. Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute URL with a query string." },
      param: {
        type: "string",
        description:
          "Redirect parameter to test (e.g. next, url, redirect). " +
          "Defaults to all.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const params = targetParams(url, input.param);
    if (params.length === 0) {
      return { content: "No query parameters to test.", isError: true };
    }

    const canary = "https://evil.example/basilisk";
    const lines: string[] = [];
    for (const name of params) {
      const res = await probeRequest(withParam(url, name, canary));
      const loc = res.location ?? "";
      const inBody =
        /http-equiv=["']?refresh/i.test(res.body) &&
        res.body.includes("evil.example");
      if (
        (res.status >= 300 &&
          res.status < 400 &&
          loc.includes("evil.example")) ||
        inBody
      ) {
        lines.push(`  [!] ${name}: redirects off-site → ${loc || "meta/JS"}`);
      } else {
        lines.push(
          `  [ ] ${name}: no off-site redirect (status ${res.status})`,
        );
      }
    }

    const hit = lines.some((l) => l.startsWith("  [!]"));
    return {
      content:
        `Open-redirect probe on ${url.href}\n${lines.join("\n")}\n` +
        (hit ? "Off-site redirect confirmed." : "No open redirect."),
    };
  },
};

/** Internal endpoints a vulnerable server might fetch on our behalf. */
const SSRF_TARGETS = [
  "http://169.254.169.254/latest/meta-data/",
  "http://127.0.0.1/",
  "http://localhost/",
];

/**
 * Heuristic SSRF probe. Injects internal/cloud-metadata URLs into a parameter
 * and reports responses that diverge from a benign baseline or leak metadata
 * markers. Best paired with an out-of-band callback for confirmation.
 */
export const ssrfProbe: Tool = {
  name: "ssrf_probe",
  description:
    "Heuristic SSRF probe: injects internal/cloud-metadata URLs into a " +
    "parameter and reports divergent or metadata-leaking responses. " +
    "Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute URL with a query string." },
      param: {
        type: "string",
        description:
          "Parameter that takes a URL/host. Defaults to every query parameter.",
      },
      callback_url: {
        type: "string",
        description:
          "Optional out-of-band URL to inject for confirmation (you " +
          "watch it externally).",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const params = targetParams(url, input.param);
    if (params.length === 0) {
      return { content: "No query parameters to test.", isError: true };
    }

    const injections =
      typeof input.callback_url === "string" && input.callback_url.trim() !== ""
        ? [...SSRF_TARGETS, input.callback_url]
        : SSRF_TARGETS;

    const lines: string[] = [];
    for (const name of params) {
      const base = await probeRequest(
        withParam(url, name, "http://example.com/"),
      );
      for (const target of injections) {
        const res = await probeRequest(withParam(url, name, target), {
          timeoutMs: 8000,
        });
        const leak = /ami-id|instance-id|iam\/|meta-data|computeMetadata/i.test(
          res.body,
        );
        const diverges =
          res.error === undefined &&
          (res.status !== base.status ||
            Math.abs(res.body.length - base.body.length) > 64);
        if (leak) lines.push(`  [!] ${name} ← ${target}: metadata leaked`);
        else if (diverges)
          lines.push(
            `  [~] ${name} ← ${target}: response diverges ` +
              `(status ${res.status}, ${res.body.length}b)`,
          );
      }
    }

    return {
      content:
        `SSRF probe on ${url.href}\n` +
        (lines.length > 0
          ? `${lines.join("\n")}\nVerify (out-of-band) before recording.`
          : "  No SSRF indicators."),
    };
  },
};
