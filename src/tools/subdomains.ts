/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { Resolver } from "node:dns/promises";
import type { Tool } from "./types.ts";
import { loadWordlist } from "./wordlists.ts";

const MAX_LABELS = 150;
const CONCURRENCY = 16;

/** Default label list for a quick pass when the caller supplies none. */
const COMMON_LABELS = [
  "www",
  "mail",
  "ftp",
  "webmail",
  "smtp",
  "pop",
  "ns1",
  "ns2",
  "dns",
  "admin",
  "portal",
  "api",
  "dev",
  "staging",
  "test",
  "vpn",
  "remote",
  "gitlab",
  "git",
  "jenkins",
  "grafana",
  "kibana",
  "app",
  "cdn",
  "static",
  "shop",
  "blog",
  "docs",
  "status",
  "mx",
  "autodiscover",
  "cpanel",
  "m",
];

function isDomain(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i.test(value)
  );
}

/**
 * DNS-based subdomain brute force. Queries public resolvers for
 * `<label>.domain` candidates — it never connects to the target's own
 * servers — so, like `dns_lookup`, it is not gated. Hard-capped at 150
 * labels with a bounded pool.
 */
export const subdomainEnum: Tool = {
  name: "subdomain_enum",
  description:
    "Discover subdomains by resolving <label>.<domain> candidates via " +
    "DNS. Queries public resolvers, not the target; capped at 150 labels.",
  schema: {
    type: "object",
    properties: {
      domain: { type: "string", description: "Base domain, e.g. example.com" },
      labels: {
        type: "array",
        items: { type: "string" },
        description:
          "Subdomain labels to try. Defaults to a common-labels list.",
      },
      wordlist: {
        type: "string",
        description:
          "Name of a wordlist under the basilisk wordlists dir, or a " +
          "path to a wordlist file.",
      },
    },
    required: ["domain"],
    additionalProperties: false,
  },

  async run(input) {
    const { domain, labels, wordlist } = input;
    if (!isDomain(domain)) {
      return { content: "Invalid domain.", isError: true };
    }

    let source: string[];
    if (Array.isArray(labels) && labels.length > 0) {
      source = labels.map(String);
    } else if (typeof wordlist === "string" && wordlist.trim() !== "") {
      try {
        source = loadWordlist(wordlist, MAX_LABELS);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        return { content: reason, isError: true };
      }
    } else {
      source = COMMON_LABELS;
    }

    const candidates = source
      .map((l) => l.trim().toLowerCase())
      .filter((l) => /^[a-z0-9-]+$/.test(l))
      .slice(0, MAX_LABELS);

    const resolver = new Resolver({ timeout: 4000, tries: 1 });
    const found: string[] = [];
    let cursor = 0;

    async function worker() {
      for (;;) {
        const index = cursor;
        cursor += 1;
        const label = candidates[index];
        if (label === undefined) return;
        const fqdn = `${label}.${domain}`;
        try {
          const addrs = await resolver.resolve4(fqdn);
          if (addrs.length > 0) found.push(`${fqdn} → ${addrs.join(", ")}`);
        } catch {
          // NXDOMAIN or no A record — not a hit.
        }
      }
    }

    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, candidates.length) }, worker),
    );
    found.sort();

    const summary =
      `Tried ${candidates.length} labels under ${domain} — ` +
      `${found.length} resolved.`;
    return {
      content:
        found.length > 0
          ? `${summary}\n${found.map((f) => `  ${f}`).join("\n")}`
          : `${summary}\n  (none resolved)`,
    };
  },
};
