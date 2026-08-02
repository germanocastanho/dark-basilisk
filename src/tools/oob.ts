/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { randomUUID } from "node:crypto";
import type { Tool } from "./types.ts";

const MAX_INTERACTIONS = 500;

interface Interaction {
  at: string;
  method: string;
  path: string;
  from: string;
  userAgent: string;
}

/**
 * Session-lived out-of-band listener. Blind SSRF/XXE payloads point a target at
 * this HTTP endpoint; a callback here confirms the vulnerability out of band.
 * Kept as a module singleton so it persists across tool calls within a session.
 */
let server: ReturnType<typeof Bun.serve> | null = null;
let token = "";
let interactions: Interaction[] = [];

function handle(req: Request, from: string): Response {
  const url = new URL(req.url);
  interactions.push({
    at: new Date().toISOString(),
    method: req.method,
    path: url.pathname + url.search,
    from,
    userAgent: req.headers.get("user-agent") ?? "",
  });
  if (interactions.length > MAX_INTERACTIONS) {
    interactions = interactions.slice(-MAX_INTERACTIONS);
  }
  return new Response("ok\n");
}

/**
 * Start the out-of-band HTTP listener and return the callback URL to feed into
 * blind SSRF/XXE payloads. Opens a listening socket (host state), so it is
 * gated. The target must be able to reach `host` — pass a routable address.
 */
export const oobStart: Tool = {
  name: "oob_start",
  description:
    "Start a session-lived out-of-band HTTP listener and return a callback URL for confirming blind SSRF/XXE. The target must be able to reach the given host.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      host: {
        type: "string",
        description:
          "Host/IP the target will use to reach this listener (default localhost — set a routable address for real targets).",
      },
      port: {
        type: "integer",
        description: "Port to bind (default an ephemeral free port).",
      },
    },
    additionalProperties: false,
  },

  async run(input) {
    const host =
      typeof input.host === "string" && input.host.trim() !== ""
        ? input.host.trim()
        : "localhost";

    if (!server) {
      token = randomUUID().slice(0, 8);
      const port = Number.isInteger(input.port) ? (input.port as number) : 0;
      try {
        server = Bun.serve({
          port,
          hostname: "0.0.0.0",
          fetch(req, srv) {
            const from = srv.requestIP(req)?.address ?? "unknown";
            return handle(req, from);
          },
        });
      } catch (err) {
        return {
          content: `Cannot start listener: ${err instanceof Error ? err.message : String(err)}`,
          isError: true,
        };
      }
    }

    const url = `http://${host}:${server.port}/${token}`;
    return {
      content:
        `OOB listener up on 0.0.0.0:${server.port}.\n` +
        `Callback URL: ${url}\n` +
        `Inject it as callback_url in ssrf_probe / xxe_probe, then oob_poll for hits.`,
    };
  },
};

/**
 * Return interactions the out-of-band listener has captured, newest last.
 * Read-only, so it is not gated. Pass `clear` to drain the buffer after
 * reading.
 */
export const oobPoll: Tool = {
  name: "oob_poll",
  description:
    "Return out-of-band interactions captured by the listener (a hit confirms blind SSRF/XXE). Optionally clear the buffer after reading.",
  risky: false,
  schema: {
    type: "object",
    properties: {
      clear: {
        type: "boolean",
        description: "Drain the buffer after reading (default false).",
      },
    },
    additionalProperties: false,
  },

  async run(input) {
    if (!server) {
      return { content: "No OOB listener running. Start one with oob_start." };
    }
    const captured = [...interactions];
    if (input.clear === true) interactions = [];

    if (captured.length === 0) {
      return { content: `No interactions yet on port ${server.port}.` };
    }
    const lines = captured.map(
      (i) =>
        `  [${i.at}] ${i.method} ${i.path} from ${i.from} (${i.userAgent})`,
    );
    return {
      content: `${captured.length} OOB interaction(s):\n${lines.join("\n")}`,
    };
  },
};

/** Stop the out-of-band listener and drop captured interactions. */
export const oobStop: Tool = {
  name: "oob_stop",
  description: "Stop the out-of-band listener and clear captured interactions.",
  risky: false,
  schema: { type: "object", properties: {}, additionalProperties: false },

  async run() {
    if (!server) return { content: "No OOB listener running." };
    server.stop(true);
    server = null;
    const count = interactions.length;
    interactions = [];
    token = "";
    return {
      content: `OOB listener stopped. Dropped ${count} interaction(s).`,
    };
  },
};
