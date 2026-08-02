/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { Socket } from "node:net";
import type { Tool } from "./types.ts";

const MAX_PORTS = 200;
const CONCURRENCY = 32;
const CONNECT_TIMEOUT_MS = 2000;

/** Common service ports probed when the caller does not specify a list. */
const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306,
  3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
];

/** Attempt a TCP connect; resolve true if the port accepts the connection. */
function isOpen(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket();
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

/** Scan ports with a bounded worker pool so the host is not hammered. */
async function scan(host: string, ports: number[]): Promise<number[]> {
  const open: number[] = [];
  let cursor = 0;
  async function worker() {
    for (;;) {
      const index = cursor;
      cursor += 1;
      const port = ports[index];
      if (port === undefined) return;
      if (await isOpen(host, port)) open.push(port);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, ports.length) }, worker),
  );
  return open.sort((a, b) => a - b);
}

/**
 * Native TCP connect scan — no nmap dependency. Reaches the target, so it is
 * gated, and hard-capped at 200 ports with a bounded pool so it cannot be turned
 * into a flood. Reports open ports only.
 */
export const tcpScan: Tool = {
  name: "tcp_scan",
  description:
    "TCP connect scan of a host (no nmap needed). Reaches the target; capped at 200 ports. Reports open ports.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      host: { type: "string", description: "Hostname or IP to scan." },
      ports: {
        type: "array",
        items: { type: "integer", minimum: 1, maximum: 65535 },
        description: "Ports to probe. Defaults to a common-services list.",
      },
    },
    required: ["host"],
    additionalProperties: false,
  },

  async run(input) {
    const { host, ports } = input;
    if (typeof host !== "string" || host.length === 0) {
      return { content: "Missing host.", isError: true };
    }

    const list = (
      Array.isArray(ports) && ports.length > 0
        ? ports
            .map(Number)
            .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
        : COMMON_PORTS
    ).slice(0, MAX_PORTS);

    if (list.length === 0) {
      return { content: "No valid ports to scan.", isError: true };
    }

    const open = await scan(host, list);
    const summary = `Scanned ${list.length} ports on ${host} — ${open.length} open.`;
    return {
      content:
        open.length > 0
          ? `${summary}\n  open: ${open.join(", ")}`
          : `${summary}\n  (no open ports in the scanned set)`,
    };
  },
};
