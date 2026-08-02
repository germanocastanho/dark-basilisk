/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { Resolver } from "node:dns/promises";
import type { Tool } from "./types.ts";

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] as const;
type RecordType = (typeof RECORD_TYPES)[number];

function isHostname(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i.test(value)
  );
}

/**
 * Passive DNS reconnaissance. Read-only and low risk, so it runs without a gate.
 * Resolves the common record types for a hostname and reports what answered.
 */
export const dnsLookup: Tool = {
  name: "dns_lookup",
  description:
    "Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME) for a hostname. Read-only reconnaissance.",
  schema: {
    type: "object",
    properties: {
      hostname: {
        type: "string",
        description: "Fully qualified domain name, e.g. example.com",
      },
      types: {
        type: "array",
        items: { type: "string", enum: [...RECORD_TYPES] },
        description: "Record types to query. Defaults to all common types.",
      },
    },
    required: ["hostname"],
    additionalProperties: false,
  },

  async run(input) {
    const { hostname, types } = input;
    if (!isHostname(hostname)) {
      return { content: "Invalid hostname.", isError: true };
    }

    const wanted: RecordType[] =
      Array.isArray(types) && types.length > 0
        ? types.filter((t): t is RecordType =>
            RECORD_TYPES.includes(t as RecordType),
          )
        : [...RECORD_TYPES];

    const resolver = new Resolver({ timeout: 5000, tries: 2 });
    const lines: string[] = [];

    for (const type of wanted) {
      try {
        const records = await resolver.resolve(hostname, type);
        lines.push(`${type}: ${JSON.stringify(records)}`);
      } catch (err) {
        const code = err instanceof Error ? err.message : String(err);
        lines.push(`${type}: none (${code})`);
      }
    }

    return { content: `DNS records for ${hostname}\n${lines.join("\n")}` };
  },
};
