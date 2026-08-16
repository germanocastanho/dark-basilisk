/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { createHmac } from "node:crypto";
import type { Tool } from "./types.ts";
import { loadWordlist } from "./wordlists.ts";

const MAX_SECRETS = 5000;

/** A handful of notoriously common JWT signing secrets. */
const DEFAULT_SECRETS = [
  "secret",
  "password",
  "123456",
  "changeme",
  "jwt",
  "admin",
  "key",
  "your-256-bit-secret",
  "supersecret",
  "s3cr3t",
  "test",
  "private",
];

function b64urlDecode(part: string): string {
  const padded = part.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf8");
}

function hs256(signingInput: string, secret: string): string {
  return createHmac("sha256", secret)
    .update(signingInput)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Decode and audit a JWT: reports header/claims, flags weak configurations
 * (`alg:none`, missing `exp`), and — for HS256 — attempts an offline secret
 * crack against a wordlist. Fully offline, so it runs without approval.
 */
export const jwtInspect: Tool = {
  name: "jwt_inspect",
  description:
    "Decode and audit a JWT (header, claims), flag weak settings " +
    "(alg=none, missing exp), and attempt an offline HS256 secret crack " +
    "against a wordlist. Offline.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      token: {
        type: "string",
        description: "The JWT (three dot-separated parts).",
      },
      secrets: {
        type: "array",
        items: { type: "string" },
        description:
          "Candidate HS256 secrets to try. Defaults to a built-in list.",
      },
      wordlist: {
        type: "string",
        description: "Named wordlist or path of candidate secrets.",
      },
    },
    required: ["token"],
    additionalProperties: false,
  },

  async run(input) {
    const token = typeof input.token === "string" ? input.token.trim() : "";
    const parts = token.split(".");
    if (parts.length !== 3) {
      return {
        content: "Not a JWT (expected three dot-separated parts).",
        isError: true,
      };
    }
    const [h, p, sig] = parts as [string, string, string];

    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(b64urlDecode(h));
      claims = JSON.parse(b64urlDecode(p));
    } catch {
      return {
        content: "Could not base64url-decode the token.",
        isError: true,
      };
    }

    const alg = String(header.alg ?? "?");
    const flags: string[] = [];
    if (/^none$/i.test(alg)) {
      flags.push("[!] alg=none — signature not verified; forge freely");
    }
    if (claims.exp === undefined)
      flags.push("[!] no `exp` — token never expires");
    else if (typeof claims.exp === "number" && claims.exp * 1000 < Date.now()) {
      flags.push("[~] token is expired");
    }

    let crack = "";
    if (/^hs256$/i.test(alg)) {
      let secrets: string[];
      try {
        secrets =
          typeof input.wordlist === "string" && input.wordlist.trim() !== ""
            ? loadWordlist(input.wordlist, MAX_SECRETS)
            : Array.isArray(input.secrets) && input.secrets.length > 0
              ? input.secrets.map(String).slice(0, MAX_SECRETS)
              : DEFAULT_SECRETS;
      } catch (err) {
        return {
          content: err instanceof Error ? err.message : String(err),
          isError: true,
        };
      }
      const signingInput = `${h}.${p}`;
      const found = secrets.find((s) => hs256(signingInput, s) === sig);
      crack =
        found !== undefined
          ? `\n[!] HS256 secret CRACKED: "${found}" (tried ${secrets.length})`
          : `\n[ ] HS256 secret not in list (tried ${secrets.length})`;
    }

    return {
      content:
        `JWT inspect\n  alg: ${alg}\n  header: ${JSON.stringify(header)}\n` +
        `  claims: ${JSON.stringify(claims)}\n` +
        (flags.length > 0
          ? `  ${flags.join("\n  ")}`
          : "  no weak-config flags") +
        crack,
    };
  },
};
