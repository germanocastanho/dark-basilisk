/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import { boundedPool, parseHttpUrl, probeRequest } from "./http.ts";
import { loadWordlist } from "./wordlists.ts";

const MAX_ITEMS = 150;
const CONCURRENCY = 8;

/** Resolve a candidate list: explicit array > wordlist > built-in default. */
function resolveList(
  explicit: unknown,
  wordlist: unknown,
  fallback: string[],
): string[] {
  if (Array.isArray(explicit) && explicit.length > 0) {
    return explicit.map(String).slice(0, MAX_ITEMS);
  }
  if (typeof wordlist === "string" && wordlist.trim() !== "") {
    return loadWordlist(wordlist, MAX_ITEMS);
  }
  return fallback.slice(0, MAX_ITEMS);
}

const DEFAULT_PARAMS = [
  "id",
  "user",
  "page",
  "q",
  "search",
  "next",
  "url",
  "redirect",
  "file",
  "path",
  "lang",
  "debug",
  "admin",
  "token",
  "callback",
  "return",
  "dest",
  "view",
  "action",
  "cmd",
];

/**
 * Discover hidden query parameters: send a unique canary as each candidate
 * parameter and flag those that change the response or reflect the canary.
 * Bounded worker pool, capped at 150 candidates.
 */
export const paramDiscover: Tool = {
  name: "param_discover",
  description:
    "Discover hidden query parameters by testing candidate names for " +
    "reflection or response changes. Active against the target; capped " +
    "at 150.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute base URL to test." },
      params: {
        type: "array",
        items: { type: "string" },
        description: "Candidate parameter names. Defaults to a built-in list.",
      },
      wordlist: {
        type: "string",
        description: "Named wordlist or path, used when `params` is omitted.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };

    let candidates: string[];
    try {
      candidates = resolveList(input.params, input.wordlist, DEFAULT_PARAMS);
    } catch (err) {
      return {
        content: err instanceof Error ? err.message : String(err),
        isError: true,
      };
    }

    const base = await probeRequest(url);
    const canary = `bx${Math.random().toString(36).slice(2, 8)}`;
    const hits = await boundedPool(candidates, CONCURRENCY, async (name) => {
      const t = new URL(url.href);
      t.searchParams.set(name, canary);
      const res = await probeRequest(t);
      const reflected = res.body.includes(canary);
      const changed =
        res.error === undefined &&
        (res.status !== base.status ||
          Math.abs(res.body.length - base.body.length) > 32);
      const reflectedNote = reflected ? " (reflected)" : "";
      const changedNote = changed
        ? ` (status ${res.status}, ${res.body.length}b)`
        : "";
      return reflected || changed
        ? `  [!] ${name}${reflectedNote}${changedNote}`
        : null;
    });

    const found = hits.filter((h): h is string => h !== null);
    return {
      content:
        `Parameter discovery on ${url.href} — tested ${candidates.length}\n` +
        (found.length > 0 ? found.join("\n") : "  (no interesting parameters)"),
    };
  },
};

const DEFAULT_VHOSTS = [
  "admin",
  "dev",
  "test",
  "staging",
  "api",
  "internal",
  "beta",
  "portal",
  "dashboard",
  "vpn",
  "mail",
  "git",
  "jenkins",
  "grafana",
  "kibana",
];

/**
 * Virtual-host discovery: send requests to one endpoint while varying the Host
 * header, and report Host values whose response diverges from a baseline —
 * exposing internal or unlinked vhosts. Capped at 150 candidates.
 */
export const vhostEnum: Tool = {
  name: "vhost_enum",
  description:
    "Virtual-host discovery by brute-forcing the Host header against " +
    "one endpoint and diffing responses. Active against the target; " +
    "capped at 150.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description:
          "Endpoint to hit (often an IP or bare host), e.g. http://1.2.3.4",
      },
      domain: {
        type: "string",
        description:
          "Base domain; candidates become `<label>.<domain>`. If " +
          "omitted, labels are used as-is.",
      },
      hosts: {
        type: "array",
        items: { type: "string" },
        description: "Explicit Host values (full hostnames) to try.",
      },
      wordlist: {
        type: "string",
        description: "Named wordlist or path of labels/hostnames.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };

    let labels: string[];
    try {
      labels = resolveList(input.hosts, input.wordlist, DEFAULT_VHOSTS);
    } catch (err) {
      return {
        content: err instanceof Error ? err.message : String(err),
        isError: true,
      };
    }
    const domain = typeof input.domain === "string" ? input.domain.trim() : "";
    const explicit = Array.isArray(input.hosts) && input.hosts.length > 0;
    const candidates = labels.map((l) =>
      explicit || domain === "" || l.includes(".") ? l : `${l}.${domain}`,
    );

    const baseline = await probeRequest(url, {
      headers: { Host: `bx${Math.random().toString(36).slice(2, 8)}.invalid` },
    });
    const hits = await boundedPool(candidates, CONCURRENCY, async (host) => {
      const res = await probeRequest(url, { headers: { Host: host } });
      if (res.error) return null;
      const diverges =
        res.status !== baseline.status ||
        Math.abs(res.body.length - baseline.body.length) > 48;
      return diverges
        ? `  [!] ${host} → status ${res.status}, ${res.body.length}b`
        : null;
    });

    const found = hits.filter((h): h is string => h !== null);
    return {
      content:
        `Vhost enumeration on ${url.href} — tested ${candidates.length}\n` +
        `(baseline: status ${baseline.status}, ${baseline.body.length}b)\n` +
        (found.length > 0 ? found.join("\n") : "  (no distinct vhosts)"),
    };
  },
};

const INTROSPECTION_QUERY = JSON.stringify({
  query: "query{__schema{queryType{name} mutationType{name} types{name kind}}}",
});

/**
 * GraphQL introspection: POST a schema-introspection query and summarize the
 * exposed types, query, and mutation roots. Introspection left on in production
 * is itself a finding.
 */
export const graphqlIntrospect: Tool = {
  name: "graphql_introspect",
  description:
    "Send a GraphQL introspection query and summarize exposed types " +
    "and root operations. Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "GraphQL endpoint, e.g. https://target.example/graphql",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };

    const res = await probeRequest(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: INTROSPECTION_QUERY,
    });
    if (res.error) {
      return { content: `Request failed: ${res.error}`, isError: true };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(res.body);
    } catch {
      return {
        content:
          `No JSON schema returned (status ${res.status}). ` +
          "Introspection likely disabled.",
      };
    }

    const schema = (parsed as { data?: { __schema?: Record<string, unknown> } })
      ?.data?.__schema;
    if (!schema) {
      return {
        content:
          `Response had no __schema (status ${res.status}). ` +
          "Introspection likely disabled.",
      };
    }
    const types = Array.isArray(schema.types) ? schema.types : [];
    const names = types
      .map((t) => (t as { name?: string }).name)
      .filter((n): n is string => typeof n === "string" && !n.startsWith("__"))
      .slice(0, 60);
    const q = (schema.queryType as { name?: string })?.name ?? "?";
    const m = (schema.mutationType as { name?: string })?.name ?? "none";

    return {
      content:
        `[!] GraphQL introspection ENABLED at ${url.href}\n` +
        `  query root: ${q}\n  mutation root: ${m}\n` +
        `  ${names.length} user types: ${names.join(", ")}`,
    };
  },
};

const EXPOSURE_PATHS = [
  ".git/HEAD",
  ".git/config",
  ".env",
  ".env.local",
  ".env.production",
  "config.php.bak",
  "backup.zip",
  "backup.tar.gz",
  "db.sql",
  "dump.sql",
  ".DS_Store",
  "wp-config.php.bak",
];

/**
 * Sensitive-file exposure check: probe for leaked VCS/config/backup artifacts
 * (`.git/HEAD`, `.env`, `*.sql`, backups). A readable `.git` or `.env` is a
 * high-severity finding.
 */
export const gitExpose: Tool = {
  name: "git_expose",
  description:
    "Check a base URL for exposed VCS, env, and backup artifacts " +
    "(.git/HEAD, .env, *.sql, backups). Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      base_url: {
        type: "string",
        description: "Base URL, e.g. https://target.example/",
      },
    },
    required: ["base_url"],
    additionalProperties: false,
  },

  async run(input) {
    const raw = typeof input.base_url === "string" ? input.base_url : "";
    const base = parseHttpUrl(raw.endsWith("/") ? raw : `${raw}/`);
    if (!base)
      return { content: "Missing or malformed base_url.", isError: true };

    const hits = await boundedPool(
      EXPOSURE_PATHS,
      CONCURRENCY,
      async (path) => {
        const res = await probeRequest(new URL(path, base));
        if (res.error || res.status !== 200 || res.body.length === 0)
          return null;
        let note = "";
        if (path === ".git/HEAD" && /^ref:\s/.test(res.body))
          note = " (valid git ref!)";
        if (path.startsWith(".env") && /[A-Z_]+=/.test(res.body))
          note = " (env vars!)";
        return `  [!] ${res.status} /${path} — ${res.body.length}b${note}`;
      },
    );

    const found = hits.filter((h): h is string => h !== null);
    return {
      content:
        `Exposure check on ${base.href} — probed ${EXPOSURE_PATHS.length}\n` +
        (found.length > 0
          ? `${found.join("\n")}\nExposed artifacts — high severity.`
          : "  (no exposed artifacts)"),
    };
  },
};

/**
 * Public cloud-storage exposure check. Given a bucket name or endpoint URL,
 * checks whether an S3/GCS bucket lists its contents anonymously.
 */
export const cloudStorageCheck: Tool = {
  name: "cloud_storage_check",
  description:
    "Check whether a cloud storage bucket (S3/GCS) is publicly " +
    "listable. Accepts a bucket name or an endpoint URL.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      bucket: {
        type: "string",
        description: "Bucket name (assumed S3) — checked on S3 and GCS.",
      },
      url: {
        type: "string",
        description: "Explicit bucket endpoint URL to check instead.",
      },
    },
    additionalProperties: false,
  },

  async run(input) {
    const endpoints: string[] = [];
    if (typeof input.url === "string" && input.url.trim() !== "") {
      endpoints.push(input.url);
    } else if (typeof input.bucket === "string" && input.bucket.trim() !== "") {
      const b = encodeURIComponent(input.bucket.trim());
      endpoints.push(
        `https://${b}.s3.amazonaws.com/`,
        `https://storage.googleapis.com/${b}`,
      );
    } else {
      return { content: "Provide `bucket` or `url`.", isError: true };
    }

    const lines: string[] = [];
    for (const ep of endpoints) {
      const url = parseHttpUrl(ep);
      if (!url) {
        lines.push(`  [ ] ${ep}: malformed`);
        continue;
      }
      const res = await probeRequest(url);
      if (res.error) {
        lines.push(`  [ ] ${ep}: ${res.error}`);
      } else if (
        res.status === 200 &&
        /<ListBucketResult|<\?xml.*Contents|"items"/i.test(res.body)
      ) {
        lines.push(`  [!] ${ep}: PUBLIC & listable (status 200)`);
      } else if (res.status === 403) {
        lines.push(`  [~] ${ep}: exists, listing denied (403)`);
      } else {
        lines.push(`  [ ] ${ep}: status ${res.status}`);
      }
    }

    return { content: `Cloud storage check\n${lines.join("\n")}` };
  },
};
