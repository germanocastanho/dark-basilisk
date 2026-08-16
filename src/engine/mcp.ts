/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Tool } from "../tools/types.ts";

/**
 * A stdio MCP server to launch and borrow tools from. `command` + `args` spawn
 * the server process; `env` adds to the inherited-safe defaults.
 */
export interface McpServerConfig {
  name: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

/** How long to wait for a server to connect and enumerate its tools. */
const CONNECT_TIMEOUT_MS = 15_000;

export interface McpConnections {
  /** Wrapped tools ready to register, namespaced `mcp__<server>__<tool>`. */
  tools: Tool[];
  /** Servers that connected, with how many tools each contributed. */
  connected: { name: string; toolCount: number }[];
  /** Servers that failed, with a short reason. */
  errors: { name: string; message: string }[];
  /** Shut every connected server down. Call on session end. */
  close(): Promise<void>;
}

const timeout = (ms: number): Promise<never> =>
  new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms),
  );

/**
 * Flatten an MCP tool result's content blocks into plain text for the
 * model.
 */
function renderResult(content: unknown): string {
  if (!Array.isArray(content)) return "(no content)";
  const parts: string[] = [];
  for (const block of content) {
    const b = block as Record<string, unknown>;
    if (b.type === "text" && typeof b.text === "string") parts.push(b.text);
    else if (b.type === "image") parts.push("[image omitted]");
    else if (b.type === "audio") parts.push("[audio omitted]");
    else if (b.type === "resource") parts.push("[resource omitted]");
  }
  return parts.length > 0 ? parts.join("\n") : "(no textual content)";
}

/**
 * Wrap one MCP tool as a basilisk Tool. Every MCP call reaches an external
 * process or service, so it is gated behind the approval gate (`risky`). The
 * name is namespaced to avoid colliding with built-ins or other servers.
 */
function wrapTool(
  server: string,
  client: Client,
  def: { name: string; description?: string; inputSchema: unknown },
): Tool {
  const schema = def.inputSchema as { type: "object" } & Record<
    string,
    unknown
  >;
  return {
    name: `mcp__${server}__${def.name}`,
    description:
      def.description ?? `MCP tool "${def.name}" from server "${server}".`,
    schema:
      schema && schema.type === "object"
        ? schema
        : { type: "object", properties: {}, additionalProperties: true },
    risky: true,
    async run(input) {
      try {
        const result = await client.callTool({
          name: def.name,
          arguments: input,
        });
        return {
          content: renderResult(result.content),
          isError: result.isError === true,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { content: `MCP call failed: ${message}`, isError: true };
      }
    },
  };
}

/**
 * Connect every configured stdio MCP server, enumerate its tools, and wrap them
 * for the registry. A server that fails to connect or list tools is recorded in
 * `errors` and skipped — one bad server never blocks startup or the others.
 */
export async function connectMcpServers(
  servers: McpServerConfig[],
): Promise<McpConnections> {
  const tools: Tool[] = [];
  const connected: { name: string; toolCount: number }[] = [];
  const errors: { name: string; message: string }[] = [];
  const clients: Client[] = [];

  for (const server of servers) {
    const client = new Client({ name: "dark-basilisk", version: "0.1.0" });
    const transport = new StdioClientTransport({
      command: server.command,
      args: server.args,
      env: server.env
        ? { ...getDefaultEnvironment(), ...server.env }
        : undefined,
    });
    try {
      await Promise.race([
        client.connect(transport),
        timeout(CONNECT_TIMEOUT_MS),
      ]);
      const listed = await Promise.race([
        client.listTools(),
        timeout(CONNECT_TIMEOUT_MS),
      ]);
      for (const def of listed.tools)
        tools.push(wrapTool(server.name, client, def));
      connected.push({ name: server.name, toolCount: listed.tools.length });
      clients.push(client);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push({ name: server.name, message });
      await client.close().catch(() => {});
    }
  }

  return {
    tools,
    connected,
    errors,
    async close() {
      await Promise.all(clients.map((c) => c.close().catch(() => {})));
    },
  };
}

/**
 * A context block naming the connected MCP servers, or null if none
 * connected.
 */
export function mcpCatalog(
  connected: { name: string; toolCount: number }[],
): string | null {
  if (connected.length === 0) return null;
  const lines = connected.map(
    (s) => `- ${s.name} (${s.toolCount} tool${s.toolCount === 1 ? "" : "s"})`,
  );
  return (
    "### CONNECTED MCP SERVERS\n\n" +
    "External tool servers are connected. Their tools are named " +
    "`mcp__<server>__<tool>` and each call requires operator approval.\n\n" +
    lines.join("\n")
  );
}
