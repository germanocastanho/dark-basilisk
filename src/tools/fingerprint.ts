/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";

/** Security response headers we check for, with a short note on each. */
const SECURITY_HEADERS: Array<[string, string]> = [
  ["strict-transport-security", "HSTS — forces HTTPS"],
  ["content-security-policy", "CSP — mitigates XSS/injection"],
  ["x-frame-options", "clickjacking protection"],
  ["x-content-type-options", "blocks MIME sniffing"],
  ["referrer-policy", "controls referrer leakage"],
  ["permissions-policy", "restricts browser features"],
];

/** Headers that tend to leak stack details. */
const DISCLOSURE_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "via",
];

/**
 * Fingerprint a web target: fetch the root, then report disclosed stack
 * headers, which security headers are present or missing, and cookie
 * flags. Reaches the target, so it is gated behind operator approval.
 */
export const webFingerprint: Tool = {
  name: "web_fingerprint",
  description:
    "Fetch a URL and report disclosed stack headers, present/missing " +
    "security headers, and cookie flags. Reaches the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute http:// or https:// URL." },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const { url } = input;
    if (typeof url !== "string") {
      return { content: "Missing url.", isError: true };
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return { content: "Malformed URL.", isError: true };
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        content: "Only http:// and https:// are allowed.",
        isError: true,
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let response: Response;
    try {
      response = await fetch(parsed, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Request failed: ${message}`, isError: true };
    } finally {
      clearTimeout(timeout);
    }

    const header = (name: string) => response.headers.get(name);

    const disclosed = DISCLOSURE_HEADERS.map((name) => {
      const value = header(name);
      return value ? `  ${name}: ${value}` : null;
    }).filter((line): line is string => line !== null);

    const security = SECURITY_HEADERS.map(([name, note]) => {
      const present = header(name);
      const mark = present ? "present" : "MISSING";
      return `  [${mark}] ${name} — ${note}${present ? `: ${present}` : ""}`;
    });

    const cookies = response.headers.get("set-cookie");
    let cookieReport = "  (no Set-Cookie)";
    if (cookies) {
      const httpOnly = /httponly/i.test(cookies)
        ? "HttpOnly set"
        : "HttpOnly MISSING";
      const secure = /secure/i.test(cookies) ? "Secure set" : "Secure MISSING";
      cookieReport = `  ${httpOnly}; ${secure}`;
    }

    const report = [
      `${parsed.href} → HTTP ${response.status} ${response.statusText}`,
      "",
      "Disclosed stack headers:",
      disclosed.length > 0 ? disclosed.join("\n") : "  (none)",
      "",
      "Security headers:",
      security.join("\n"),
      "",
      "Cookies:",
      cookieReport,
    ];

    return { content: report.join("\n") };
  },
};
