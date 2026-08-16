/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";

const MAX_BODY_BYTES = 64 * 1024;

/**
 * Fetch a URL and return status, headers, and a truncated body. Marked risky
 * because it reaches an external host — the operator approves the target before
 * the request leaves the machine.
 */
export const httpFetch: Tool = {
  name: "http_fetch",
  description:
    "Perform a single HTTP(S) request and return status, headers, and a " +
    "truncated body. Reaches an external host.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute http:// or https:// URL." },
      method: {
        type: "string",
        enum: ["GET", "HEAD", "POST"],
        description: "HTTP method. Defaults to GET.",
      },
      body: {
        type: "string",
        description: "Optional request body for POST.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const { url, method, body } = input;
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

    const verb = typeof method === "string" ? method : "GET";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    try {
      const response = await fetch(parsed, {
        method: verb,
        body: verb === "POST" && typeof body === "string" ? body : undefined,
        redirect: "manual",
        signal: controller.signal,
      });

      const headers = [...response.headers.entries()]
        .map(([key, value]) => `${key}: ${value}`)
        .join("\n");

      const raw = verb === "HEAD" ? "" : await response.text();
      const truncated =
        raw.length > MAX_BODY_BYTES
          ? `${raw.slice(0, MAX_BODY_BYTES)}\n[truncated ` +
            `${raw.length - MAX_BODY_BYTES} bytes]`
          : raw;

      return {
        content:
          `${verb} ${parsed.href}\n` +
          `HTTP ${response.status} ${response.statusText}\n\n` +
          `${headers}\n\n${truncated}`,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Request failed: ${message}`, isError: true };
    } finally {
      clearTimeout(timeout);
    }
  },
};
