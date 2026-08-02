/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";

const PROBE_ORIGIN = "https://basilisk-probe.example";

/**
 * Probe a URL for CORS misconfiguration. Sends a crafted `Origin` header and
 * inspects the reflected `Access-Control-Allow-Origin` / `-Allow-Credentials`
 * response. Reaches the target, so it is gated. A server that reflects an
 * arbitrary origin (especially with credentials allowed) is a finding.
 */
export const corsCheck: Tool = {
  name: "cors_check",
  description:
    "Send a crafted Origin header and report whether the server reflects it (CORS misconfiguration). Reaches the target; read-only probe.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute http:// or https:// URL." },
      origin: {
        type: "string",
        description: `Origin to test with. Defaults to ${PROBE_ORIGIN}.`,
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const { url, origin } = input;
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

    const testOrigin =
      typeof origin === "string" && origin.length > 0 ? origin : PROBE_ORIGIN;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let response: Response;
    try {
      response = await fetch(parsed, {
        method: "GET",
        headers: { Origin: testOrigin },
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Request failed: ${message}`, isError: true };
    } finally {
      clearTimeout(timeout);
    }

    const acao = response.headers.get("access-control-allow-origin");
    const acac = response.headers.get("access-control-allow-credentials");

    let verdict: string;
    if (!acao) {
      verdict =
        "No Access-Control-Allow-Origin returned — CORS not enabled for this origin.";
    } else if (acao === "*") {
      verdict =
        acac === "true"
          ? "MISCONFIG: wildcard origin with credentials is rejected by browsers, but the header pairing is invalid and worth reporting."
          : "Wildcard origin (*). Permissive but standard for public APIs; credentials not allowed.";
    } else if (acao === testOrigin) {
      verdict =
        acac === "true"
          ? "FINDING: the server reflects an arbitrary Origin AND allows credentials — cross-origin credential theft is possible."
          : "FINDING: the server reflects an arbitrary Origin. Review the allowed-origin logic.";
    } else {
      verdict = `Server returned a fixed origin (${acao}); the crafted origin was not reflected.`;
    }

    const report = [
      `${parsed.href} (tested Origin: ${testOrigin})`,
      `  Access-Control-Allow-Origin: ${acao ?? "(none)"}`,
      `  Access-Control-Allow-Credentials: ${acac ?? "(none)"}`,
      "",
      `  ${verdict}`,
    ];

    return { content: report.join("\n") };
  },
};
