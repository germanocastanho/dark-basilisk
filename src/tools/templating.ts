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

/**
 * Template expressions across common engines. Each evaluates `a*b` if the
 * parameter reaches a server-side template — the product only appears in the
 * response when the expression is rendered, not when it is reflected verbatim.
 */
function sstiPayloads(
  a: number,
  b: number,
): Array<{ engine: string; p: string }> {
  return [
    { engine: "Jinja2/Twig/Angular", p: `{{${a}*${b}}}` },
    { engine: "JSP-EL/Spring", p: `\${${a}*${b}}` },
    { engine: "Thymeleaf", p: `*{${a}*${b}}` },
    { engine: "Freemarker", p: `#{${a}*${b}}` },
    { engine: "ERB/EJS", p: `<%= ${a}*${b} %>` },
    { engine: "Razor", p: `@(${a}*${b})` },
    { engine: "Handlebars/generic", p: `{${a}*${b}}` },
    { engine: "Smarty-alt", p: `\${{${a}*${b}}}` },
  ];
}

/**
 * Heuristic server-side template-injection probe. Injects an arithmetic
 * expression in several engine syntaxes into a query parameter and reports the
 * engine whose rendered product surfaces in the response. Active against the
 * target.
 */
export const sstiProbe: Tool = {
  name: "ssti_probe",
  description:
    "Heuristic SSTI probe on a URL query parameter: injects an " +
    "arithmetic expression across template engines (Jinja2, JSP-EL, " +
    "Twig, ERB, Razor, ...) and reports which renders it. Active " +
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

    // 4-digit product is distinctive enough to avoid coincidental matches.
    const a = 50 + Math.floor(Math.random() * 49);
    const b = 50 + Math.floor(Math.random() * 49);
    const product = String(a * b);

    const lines: string[] = [];
    for (const name of params) {
      const base = await probeRequest(withParam(url, name, "1"));
      let hit: string | null = null;
      for (const { engine, p } of sstiPayloads(a, b)) {
        const res = await probeRequest(withParam(url, name, p));
        if (res.error) continue;
        if (res.body.includes(product) && !base.body.includes(product)) {
          hit = `${engine} rendered ${a}*${b}=${product} via \`${p}\``;
          break;
        }
      }
      lines.push(
        hit ? `  [!] ${name}: ${hit}` : `  [ ] ${name}: no template evaluation`,
      );
    }

    const found = lines.some((l) => l.startsWith("  [!]"));
    return {
      content:
        `SSTI probe on ${url.href}\n${lines.join("\n")}\n` +
        (found
          ? "Expression evaluated — likely SSTI; verify before recording."
          : "No template evaluation."),
    };
  },
};
