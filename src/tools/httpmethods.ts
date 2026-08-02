/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";

/** Methods worth flagging when a server accepts them. */
const RISKY_METHODS: Record<string, string> = {
  PUT: "may allow arbitrary file upload",
  DELETE: "may allow resource deletion",
  TRACE: "enables Cross-Site Tracing (XST)",
  CONNECT: "may enable proxying through the server",
  PATCH: "may allow partial resource modification",
};

/**
 * Enumerate the HTTP methods a URL accepts and flag dangerous ones. Sends an
 * OPTIONS request and reads the `Allow` header; reaches the target, so it is
 * gated. Does not actually exercise the risky methods — it only reports what the
 * server advertises.
 */
export const httpMethods: Tool = {
  name: "http_methods",
  description:
    "Send OPTIONS to a URL and report the advertised HTTP methods, flagging dangerous ones (PUT/DELETE/TRACE/...). Reaches the target; read-only probe.",
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
        method: "OPTIONS",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Request failed: ${message}`, isError: true };
    } finally {
      clearTimeout(timeout);
    }

    const allow = response.headers.get("allow");
    if (!allow) {
      return {
        content: `OPTIONS ${parsed.href} → HTTP ${response.status}, no Allow header. The server may not advertise methods; probe individually if needed.`,
      };
    }

    const methods = allow
      .split(",")
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);

    const flagged = methods
      .filter((m) => m in RISKY_METHODS)
      .map((m) => `  [!] ${m} — ${RISKY_METHODS[m]}`);

    const report = [
      `OPTIONS ${parsed.href} → HTTP ${response.status}`,
      `  advertised: ${methods.join(", ")}`,
      flagged.length > 0
        ? `dangerous methods:\n${flagged.join("\n")}`
        : "  no dangerous methods advertised",
    ];

    return { content: report.join("\n") };
  },
};
