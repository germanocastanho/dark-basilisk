/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import { loadWordlist } from "./wordlists.ts";

const MAX_PATHS = 100;
const CONCURRENCY = 8;
const PER_REQUEST_TIMEOUT_MS = 8000;

/** Small built-in list used when the caller does not supply paths. */
const DEFAULT_PATHS = [
  "robots.txt",
  ".git/HEAD",
  ".env",
  "admin",
  "login",
  "api",
  "backup",
  "config.php",
  "wp-login.php",
  "phpinfo.php",
  ".well-known/security.txt",
  "sitemap.xml",
];

interface Probe {
  path: string;
  status: number | "error";
  length: number | null;
  location: string | null;
}

/** Probe a single path and classify the response. */
async function probe(base: URL, path: string): Promise<Probe> {
  const target = new URL(path.replace(/^\/+/, ""), base);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PER_REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(target, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
    });
    const len = res.headers.get("content-length");
    return {
      path,
      status: res.status,
      length: len ? Number(len) : null,
      location: res.headers.get("location"),
    };
  } catch {
    return { path, status: "error", length: null, location: null };
  } finally {
    clearTimeout(timer);
  }
}

/** Run probes with a bounded worker pool so we never flood the target. */
async function probeAll(base: URL, paths: string[]): Promise<Probe[]> {
  const results: Probe[] = [];
  let cursor = 0;
  async function worker() {
    for (;;) {
      const index = cursor;
      cursor += 1;
      const path = paths[index];
      if (path === undefined) return;
      results.push(await probe(base, path));
    }
  }
  const workers = Array.from(
    { length: Math.min(CONCURRENCY, paths.length) },
    worker,
  );
  await Promise.all(workers);
  return results;
}

/**
 * Content discovery: probe a set of paths under a base URL and report which
 * exist. Active and potentially noisy against the target, so it is gated and
 * hard-capped at 100 paths with a bounded concurrency pool.
 */
export const dirProbe: Tool = {
  name: "http_probe_paths",
  description:
    "Probe a list of paths under a base URL and report status codes (content discovery). Active against the target; capped at 100 paths.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      base_url: {
        type: "string",
        description: "Base URL, e.g. https://target.example/",
      },
      paths: {
        type: "array",
        items: { type: "string" },
        description:
          "Paths to probe (relative). Defaults to a small built-in list if omitted.",
      },
      wordlist: {
        type: "string",
        description:
          "Name of a wordlist under the basilisk wordlists dir, or a path to a wordlist file.",
      },
    },
    required: ["base_url"],
    additionalProperties: false,
  },

  async run(input) {
    const { base_url, paths, wordlist } = input;
    if (typeof base_url !== "string") {
      return { content: "Missing base_url.", isError: true };
    }

    let base: URL;
    try {
      base = new URL(base_url.endsWith("/") ? base_url : `${base_url}/`);
    } catch {
      return { content: "Malformed base_url.", isError: true };
    }
    if (base.protocol !== "http:" && base.protocol !== "https:") {
      return {
        content: "Only http:// and https:// are allowed.",
        isError: true,
      };
    }

    let source: string[];
    if (Array.isArray(paths) && paths.length > 0) {
      source = paths.map(String);
    } else if (typeof wordlist === "string" && wordlist.trim() !== "") {
      try {
        source = loadWordlist(wordlist, MAX_PATHS);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        return { content: reason, isError: true };
      }
    } else {
      source = DEFAULT_PATHS;
    }
    const list = source.slice(0, MAX_PATHS);

    const results = await probeAll(base, list);

    // Surface interesting hits first: anything that is not a 404 or an error.
    const interesting = results.filter(
      (r) => r.status !== 404 && r.status !== "error",
    );
    const ordered = [...interesting].sort((a, b) =>
      a.path.localeCompare(b.path),
    );

    const lines = ordered.map((r) => {
      const size = r.length !== null ? ` ${r.length}b` : "";
      const loc = r.location ? ` → ${r.location}` : "";
      return `  ${String(r.status).padEnd(5)} /${r.path}${size}${loc}`;
    });

    const summary = `Probed ${results.length} paths against ${base.href} — ${interesting.length} notable, ${results.length - interesting.length} were 404/error.`;

    return {
      content:
        lines.length > 0
          ? `${summary}\n${lines.join("\n")}`
          : `${summary}\n  (nothing notable)`,
    };
  },
};
