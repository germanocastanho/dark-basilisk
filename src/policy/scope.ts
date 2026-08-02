/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Tools that reach the target under test over the network. Only these are
 * gated by the scope allowlist. `run_command` is exempt: its target lives in
 * free-form argv and cannot be reliably parsed, so we cannot enforce it here.
 */
export const TARGET_REACHING_TOOLS: Set<string> = new Set([
  "http_fetch",
  "web_fingerprint",
  "tls_inspect",
  "http_probe_paths",
  "tcp_scan",
  "http_methods",
  "cors_check",
  // Red Team probes that reach the target under test.
  "sqli_probe",
  "xss_probe",
  "open_redirect_probe",
  "ssrf_probe",
  "param_discover",
  "vhost_enum",
  "graphql_introspect",
  "git_expose",
  "cloud_storage_check",
  "idor_probe",
  "credential_spray",
  "command_injection_probe",
  "path_traversal_probe",
  "xxe_probe",
  "ssti_probe",
  "xpath_injection_probe",
  "ldap_injection_probe",
  "deserialization_probe",
  "auth_bypass_probe",
  // Blue Team probe that reaches the target.
  "header_harden",
]);

const HOST_FIELDS = ["url", "base_url", "host", "target", "domain"] as const;

/** Strip surrounding brackets and any zone id from an IPv6-ish literal. */
function cleanV6(value: string): string {
  return value.replace(/^\[|\]$/g, "").split("%")[0] ?? "";
}

function parseHost(value: string): string | null {
  const raw = value.trim();
  if (!raw) return null;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);

  // A bare IPv6 literal (no scheme) must be kept whole, not split on ':'.
  if (!hasScheme) {
    const bare = cleanV6(raw);
    if (isIpv6(bare)) return bare.toLowerCase();
  }

  try {
    const host = new URL(hasScheme ? raw : `http://${raw}`).hostname;
    const clean = cleanV6(host);
    return clean ? clean.toLowerCase() : null;
  } catch {
    const host = raw.split("/")[0]?.split(":")[0];
    return host ? host.toLowerCase() : null;
  }
}

/** Pull the target host from a tool input, or null if none is present. */
export function extractTargetHost(
  input: Record<string, unknown>,
): string | null {
  for (const field of HOST_FIELDS) {
    const value = input[field];
    if (typeof value === "string") {
      const host = parseHost(value);
      if (host) return host;
    }
  }
  return null;
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) <= 255);
}

function ipv4ToUint32(value: string): number {
  return (
    value.split(".").reduce((acc, part) => (acc << 8) | Number(part), 0) >>> 0
  );
}

function inCidr4(host: string, network: string, bits: number): boolean {
  if (!isIpv4(network) || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToUint32(host) & mask) === (ipv4ToUint32(network) & mask);
}

/** Parse an IPv6 literal to its 128-bit value, or null if malformed. */
function ipv6ToBigInt(value: string): bigint | null {
  const v = cleanV6(value);
  if (!v.includes(":")) return null;

  let groups: string[];
  const parts = v.split("::");
  if (parts.length === 1) {
    groups = v.split(":");
  } else if (parts.length === 2) {
    const head = parts[0] ? parts[0]!.split(":") : [];
    const tail = parts[1] ? parts[1]!.split(":") : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array(missing).fill("0"), ...tail];
  } else {
    return null; // more than one "::"
  }

  if (groups.length !== 8) return null;
  let acc = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    acc = (acc << 16n) | BigInt(Number.parseInt(g, 16));
  }
  return acc;
}

function isIpv6(value: string): boolean {
  return ipv6ToBigInt(value) !== null;
}

function inCidr6(host: string, network: string, bits: number): boolean {
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const h = ipv6ToBigInt(host);
  const n = ipv6ToBigInt(network);
  if (h === null || n === null) return false;
  const full = (1n << 128n) - 1n;
  const mask = bits === 0 ? 0n : full ^ ((1n << BigInt(128 - bits)) - 1n);
  return (h & mask) === (n & mask);
}

/** Whether a host is covered by the scope allowlist. */
export function hostInScope(host: string, scope: string[]): boolean {
  if (scope.length === 0) return true;

  const target = host.toLowerCase();
  const hostIsIpv4 = isIpv4(target);
  const hostIsIpv6 = !hostIsIpv4 && isIpv6(target);

  for (const raw of scope) {
    const entry = raw.toLowerCase();

    if (target === entry || target.endsWith(`.${entry}`)) return true;

    if (entry.includes("/")) {
      const [network, bitsRaw] = entry.split("/");
      const bits = Number(bitsRaw);
      if (!network || bitsRaw === undefined || Number.isNaN(bits)) continue;
      if (hostIsIpv4 && inCidr4(target, network, bits)) return true;
      if (hostIsIpv6 && inCidr6(target, network, bits)) return true;
    } else if (hostIsIpv6 && isIpv6(entry)) {
      // Match different spellings of the same address (e.g. ::1 == 0:0:…:1).
      if (ipv6ToBigInt(target) === ipv6ToBigInt(entry)) return true;
    }
  }
  return false;
}

export interface ScopeCheck {
  allowed: boolean;
  host?: string;
  reason?: string;
}

/** Decide whether a tool call may proceed under the configured scope. */
export function checkScope(
  toolName: string,
  input: Record<string, unknown>,
  scope: string[],
): ScopeCheck {
  if (scope.length === 0 || !TARGET_REACHING_TOOLS.has(toolName)) {
    return { allowed: true };
  }

  const host = extractTargetHost(input);
  if (!host) return { allowed: true };

  if (hostInScope(host, scope)) return { allowed: true };

  return {
    allowed: false,
    host,
    reason: `host "${host}" is outside the configured scope`,
  };
}
