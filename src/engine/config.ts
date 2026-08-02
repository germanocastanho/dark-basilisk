/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DEFAULT_MODEL, type ModelConfig } from "./model.ts";
import type { McpServerConfig } from "./mcp.ts";

/**
 * Operator-tunable settings, read once at startup from a JSON file. Every field
 * is optional in the file; anything missing or malformed falls back to the
 * built-in default, so a partial or absent config never breaks a run.
 */
export interface Config {
  /** Model + token budget for the agent loop (the reasoning-effort knob). */
  model: ModelConfig;
  /** Wall-clock cap for a single `run_command` invocation, in milliseconds. */
  commandTimeoutMs: number;
  /** Extra binaries added to the built-in `run_command` allowlist. */
  allowedCommands: string[];
  /** In-scope hosts/CIDRs; empty disables scope enforcement. */
  scope: string[];
  /** Stdio MCP servers to connect and borrow tools from at startup. */
  mcpServers: McpServerConfig[];
}

export const DEFAULT_CONFIG: Config = {
  model: DEFAULT_MODEL,
  commandTimeoutMs: 120_000,
  allowedCommands: [],
  scope: [],
  mcpServers: [],
};

/** Path of the config file (XDG config dir by default). */
export function configPath(): string {
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  return join(base, "basilisk", "config.json");
}

function isPositiveNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Validate the `mcpServers` array. Each entry needs a non-empty `name` and
 * `command`; `args` and `env` are optional and type-checked. Malformed entries
 * are dropped so one bad server never discards the rest.
 */
function parseMcpServers(value: unknown): McpServerConfig[] {
  if (!Array.isArray(value)) return [];
  const servers: McpServerConfig[] = [];
  for (const item of value) {
    const rec = asRecord(item);
    const name = rec.name;
    const command = rec.command;
    if (typeof name !== "string" || !name) continue;
    if (typeof command !== "string" || !command) continue;
    const args = Array.isArray(rec.args)
      ? rec.args.filter((a): a is string => typeof a === "string")
      : undefined;
    const env =
      rec.env && typeof rec.env === "object"
        ? Object.fromEntries(
            Object.entries(rec.env as Record<string, unknown>).filter(
              (e): e is [string, string] => typeof e[1] === "string",
            ),
          )
        : undefined;
    servers.push({ name, command, args, env });
  }
  return servers;
}

/**
 * Load and validate the config. An absent file yields the defaults silently; a
 * malformed one warns on stderr and falls back rather than aborting the CLI.
 * Unknown keys are ignored and each known key is type-checked in isolation, so
 * one bad field never discards the rest.
 */
export function loadConfig(): Config {
  const path = configPath();

  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    // No file — the common case. Use defaults without noise.
    return {
      ...DEFAULT_CONFIG,
      model: { ...DEFAULT_MODEL },
      allowedCommands: [],
      scope: [],
      mcpServers: [],
    };
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = asRecord(JSON.parse(raw));
  } catch {
    process.stderr.write(`basilisk: ignoring malformed config at ${path}\n`);
    return {
      ...DEFAULT_CONFIG,
      model: { ...DEFAULT_MODEL },
      allowedCommands: [],
      scope: [],
      mcpServers: [],
    };
  }

  const model = asRecord(parsed.model);

  return {
    model: {
      model:
        typeof model.model === "string" ? model.model : DEFAULT_MODEL.model,
      maxTokens: isPositiveNumber(model.maxTokens)
        ? model.maxTokens
        : DEFAULT_MODEL.maxTokens,
    },
    commandTimeoutMs: isPositiveNumber(parsed.commandTimeoutMs)
      ? parsed.commandTimeoutMs
      : DEFAULT_CONFIG.commandTimeoutMs,
    allowedCommands: Array.isArray(parsed.allowedCommands)
      ? parsed.allowedCommands.filter((c): c is string => typeof c === "string")
      : [],
    scope: Array.isArray(parsed.scope)
      ? parsed.scope.filter((s): s is string => typeof s === "string")
      : [],
    mcpServers: parseMcpServers(parsed.mcpServers),
  };
}
