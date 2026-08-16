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

/** XPath engine errors that betray injection into an XPath query. */
const XPATH_ERRORS = [
  /XPathException/i,
  /MS\.Internal\.Xml/i,
  /Expression must evaluate to a node-set/i,
  /xmlXPathEval/i,
  /SimpleXMLElement::xpath/i,
  /Warning.*xpath/i,
  /unclosed token/i,
];

/**
 * Heuristic XPath-injection probe. Sends a boolean-true and boolean-false XPath
 * payload to a parameter and flags either an XPath engine error or a
 * true/false response divergence — the signature of an injectable XPath query.
 * Active against the target.
 */
export const xpathInjectionProbe: Tool = {
  name: "xpath_injection_probe",
  description:
    "Heuristic XPath-injection probe on a URL query parameter: checks " +
    "error-based and boolean-based (true vs false) signals. Active " +
    "against the target.",
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

    const lines: string[] = [];
    for (const name of params) {
      const base = await probeRequest(withParam(url, name, "1"));
      const err = await probeRequest(withParam(url, name, "'\"]|"));
      const truthy = await probeRequest(withParam(url, name, "1' or '1'='1"));
      const falsy = await probeRequest(withParam(url, name, "1' or '1'='2"));

      const signals: string[] = [];
      if (XPATH_ERRORS.some((re) => re.test(err.body))) {
        signals.push("error-based (XPath error reflected)");
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
      lines.push(
        signals.length > 0
          ? `  [!] ${name}: ${signals.join("; ")}`
          : `  [ ] ${name}: no clear signal`,
      );
    }

    const hit = lines.some((l) => l.startsWith("  [!]"));
    return {
      content:
        `XPath-injection probe on ${url.href}\n${lines.join("\n")}\n` +
        (hit
          ? "Indicators found — verify before recording."
          : "No indicators."),
    };
  },
};

/** LDAP errors that betray injection into an LDAP filter. */
const LDAP_ERRORS = [
  /javax\.naming\.NameNotFoundException/i,
  /LDAPException/i,
  /com\.sun\.jndi/i,
  /Invalid DN syntax/i,
  /supplied argument is not a valid ldap/i,
  /ldap_search/i,
  /Bad search filter/i,
];

/**
 * Heuristic LDAP-injection probe. Sends filter-breaking payloads to a parameter
 * and flags either an LDAP error or a wildcard-vs-baseline response divergence
 * — signals that user input lands in an unescaped LDAP filter. Active against
 * the target.
 */
export const ldapInjectionProbe: Tool = {
  name: "ldap_injection_probe",
  description:
    "Heuristic LDAP-injection probe on a URL query parameter: checks " +
    "error-based and wildcard-divergence signals. Active against the " +
    "target.",
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

    const lines: string[] = [];
    for (const name of params) {
      const base = await probeRequest(withParam(url, name, "1"));
      const err = await probeRequest(withParam(url, name, ")(|("));
      const wild = await probeRequest(withParam(url, name, "*"));
      const both = await probeRequest(withParam(url, name, "*)(uid=*"));

      const signals: string[] = [];
      if (LDAP_ERRORS.some((re) => re.test(err.body) || re.test(both.body))) {
        signals.push("error-based (LDAP error reflected)");
      }
      if (
        wild.error === undefined &&
        wild.status === base.status &&
        Math.abs(wild.body.length - base.body.length) > 64
      ) {
        signals.push(
          `wildcard divergence (base=${base.body.length}b vs ` +
            `*=${wild.body.length}b)`,
        );
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
        `LDAP-injection probe on ${url.href}\n${lines.join("\n")}\n` +
        (hit
          ? "Indicators found — verify before recording."
          : "No indicators."),
    };
  },
};
