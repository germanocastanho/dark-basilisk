/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { connect, type PeerCertificate } from "node:tls";
import type { Tool } from "./types.ts";

interface TlsInfo {
  protocol: string | null;
  cipher: string;
  cert: PeerCertificate;
}

/** Open a TLS connection and capture the negotiated protocol and peer cert. */
function inspect(host: string, port: number): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = connect(
      {
        host,
        port,
        servername: host,
        timeout: 10000,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        socket.end();
        resolve({ protocol, cipher: cipher?.name ?? "unknown", cert });
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("connection timed out"));
    });
    socket.on("error", reject);
  });
}

/**
 * Inspect a target's TLS certificate and negotiated parameters. Reaches the
 * target, so it is gated. Certificate validation is intentionally disabled so
 * self-signed or expired certs can still be reported rather than aborting.
 */
export const tlsInspect: Tool = {
  name: "tls_inspect",
  description:
    "Open a TLS connection to host:port and report the certificate " +
    "(subject, issuer, validity, SANs) plus protocol and cipher. " +
    "Reaches the target.",
  risky: true,
  schema: {
    type: "object",
    properties: {
      host: { type: "string", description: "Hostname to connect to." },
      port: {
        type: "integer",
        description: "TCP port. Defaults to 443.",
        minimum: 1,
        maximum: 65535,
      },
    },
    required: ["host"],
    additionalProperties: false,
  },

  async run(input) {
    const { host, port } = input;
    if (typeof host !== "string" || host.length === 0) {
      return { content: "Missing host.", isError: true };
    }
    const targetPort = typeof port === "number" ? port : 443;

    let info: TlsInfo;
    try {
      info = await inspect(host, targetPort);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `TLS connection failed: ${message}`, isError: true };
    }

    const { cert } = info;
    const subject = cert.subject?.CN ?? "(none)";
    const issuer = cert.issuer?.CN ?? "(none)";
    const sans = cert.subjectaltname ?? "(none)";
    const now = Date.now();
    const notAfter = cert.valid_to ? new Date(cert.valid_to).getTime() : NaN;
    const expiry = Number.isNaN(notAfter)
      ? "unknown"
      : notAfter < now
        ? `${cert.valid_to} (EXPIRED)`
        : cert.valid_to;

    const report = [
      `${host}:${targetPort}`,
      `  protocol: ${info.protocol ?? "unknown"}   cipher: ${info.cipher}`,
      `  subject CN: ${subject}`,
      `  issuer CN:  ${issuer}`,
      `  valid from: ${cert.valid_from ?? "unknown"}`,
      `  valid to:   ${expiry}`,
      `  SANs: ${sans}`,
    ];

    return { content: report.join("\n") };
  },
};
