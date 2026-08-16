/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import { parseHttpUrl, probeRequest } from "./http.ts";

/**
 * Signatures of native serialization formats. Their presence in a cookie,
 * hidden field, or response means the app hands serialized objects to clients —
 * a deserialization attack surface worth manual follow-up.
 */
const SER_SIGNATURES: Array<{ label: string; re: RegExp }> = [
  {
    label: "Java serialized (base64 rO0AB / hex aced0005)",
    re: /rO0AB|aced0005/i,
  },
  { label: "PHP serialized object", re: /O:\d+:"[^"]+":\d+:\{/ },
  { label: "PHP serialized array", re: /a:\d+:\{[isbd]:/ },
  { label: ".NET ViewState", re: /__VIEWSTATE|["'>]\/wEP?[A-Za-z0-9+/]{8}/ },
  { label: "Python pickle (base64 proto)", re: /\bgAS[NVM][A-Za-z0-9+/]{6}/ },
  { label: "Ruby Marshal (base64)", re: /\bBAh[A-Za-z0-9+/]{6}/ },
  {
    label: "Java JNDI/ObjectInputStream error",
    re: /ObjectInputStream|readObject|java\.io\.Serializable/,
  },
];

/**
 * Insecure-deserialization surface probe. Fetches a URL and scans its response
 * body and Set-Cookie values for native serialization signatures (Java, PHP,
 * .NET ViewState, Python pickle, Ruby Marshal). It reports exposure, not
 * exploitation — flag it, then craft a gadget chain by hand. Active against the
 * target.
 */
export const deserializationProbe: Tool = {
  name: "deserialization_probe",
  description:
    "Scan a URL's response and cookies for native serialization " +
    "signatures (Java, PHP, .NET ViewState, pickle, Ruby Marshal) to " +
    "surface a deserialization attack surface. Active against the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      url: { type: "string", description: "Absolute URL to fetch and scan." },
    },
    required: ["url"],
    additionalProperties: false,
  },

  async run(input) {
    const url = parseHttpUrl(input.url);
    if (!url) return { content: "Missing or malformed url.", isError: true };
    const res = await probeRequest(url, { redirect: "follow" });
    if (res.error) {
      return { content: `Request failed: ${res.error}`, isError: true };
    }

    const cookies = res.headers.get("set-cookie") ?? "";
    const haystack = `${cookies}\n${res.body}`;
    const lines: string[] = [];
    for (const sig of SER_SIGNATURES) {
      if (sig.re.test(haystack)) {
        const where = sig.re.test(cookies) ? "cookie" : "response";
        lines.push(`  [!] ${sig.label} (in ${where})`);
      }
    }

    return {
      content:
        `Deserialization surface on ${url.href} (HTTP ${res.status})\n` +
        (lines.length > 0
          ? `${lines.join("\n")}\nNative serialization exposed — assess ` +
            "gadget chains manually."
          : "  No native serialization signatures found."),
    };
  },
};
