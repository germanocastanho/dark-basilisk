/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Tool } from "./types.ts";

const run = promisify(execFile);

const MAX_OUTPUT_BYTES = 64 * 1024;

/**
 * Executables the agent is allowed to invoke. This allowlist is the security
 * spine of the shell tool: the model picks the binary and arguments, but only
 * these commands ever run, and every invocation still passes the approval gate.
 * Extend deliberately — each entry widens what an authorized run can do. The
 * operator can add more via `allowedCommands` in the config file.
 */
const ALLOWED = new Set<string>([
  // Baseline recon / TLS.
  "nmap",
  "dig",
  "whois",
  "host",
  "curl",
  "openssl",
  "nikto",
  "gobuster",
  "whatweb",
  "sslscan",
  "sslyze",
  "testssl.sh",
  // Red Team — discovery, fuzzing, and exploitation.
  "nuclei",
  "sqlmap",
  "ffuf",
  "feroxbuster",
  "wfuzz",
  "httpx",
  "katana",
  "subfinder",
  "amass",
  "assetfinder",
  "naabu",
  "masscan",
  "dnsx",
  "wpscan",
  "dalfox",
  "arjun",
  "gau",
  "waybackurls",
  // Red Team — network / AD / credential and offline cracking.
  "hydra",
  "medusa",
  "netexec",
  "crackmapexec",
  "enum4linux-ng",
  "smbclient",
  "john",
  "hashcat",
  // Blue Team — SAST, SCA/SBOM, secrets, and host/IDS tooling.
  "trivy",
  "grype",
  "syft",
  "semgrep",
  "gitleaks",
  "trufflehog",
  "yara",
  "lynis",
  "clamscan",
  "zeek",
  "suricata",
]);

function looksUnsafe(arg: string): boolean {
  // The arguments go straight to execFile (no shell), so operators like && or |
  // are inert. We still reject them to avoid the model believing it can chain
  // commands and then acting on a false model of what ran.
  return /[;&|`$><\n]/.test(arg) || arg.includes("$(");
}

/**
 * Run a single allowlisted security tool. Marked risky, so the dispatcher
 * requires operator approval before this executes. No shell is spawned:
 * arguments are passed as an argv array to prevent injection.
 */
export const runCommand: Tool = {
  name: "run_command",
  description:
    "Run one allowlisted security tool with explicit arguments. Covers a broad red/blue arsenal — recon (nmap, subfinder, amass, httpx), fuzzing (ffuf, feroxbuster, nuclei), exploitation (sqlmap, dalfox, wpscan), credential/network (hydra, netexec, john, hashcat), and defense (trivy, semgrep, gitleaks, yara). Requires operator approval.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      command: {
        type: "string",
        description: "Executable name. Must be on the allowlist.",
      },
      args: {
        type: "array",
        items: { type: "string" },
        description:
          "Arguments passed directly as argv, no shell interpolation.",
      },
    },
    required: ["command"],
    additionalProperties: false,
  },

  async run(input, ctx) {
    const { command, args } = input;
    const allowed = new Set([...ALLOWED, ...ctx.config.allowedCommands]);
    if (typeof command !== "string" || !allowed.has(command)) {
      return {
        content: `Command "${String(command)}" is not on the allowlist. Allowed: ${[...allowed].join(", ")}`,
        isError: true,
      };
    }

    const argv = Array.isArray(args) ? args.map(String) : [];
    const offending = argv.find(looksUnsafe);
    if (offending) {
      return {
        content: `Rejected argument with shell metacharacters: ${offending}`,
        isError: true,
      };
    }

    try {
      const { stdout, stderr } = await run(command, argv, {
        timeout: ctx.config.commandTimeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
      });
      const combined = `${stdout}${stderr ? `\n[stderr]\n${stderr}` : ""}`;
      return { content: combined.trim() || "(no output)" };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Execution failed: ${message}`, isError: true };
    }
  },
};
