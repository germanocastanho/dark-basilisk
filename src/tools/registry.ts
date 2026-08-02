/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool, ToolContext, ToolOutcome } from "./types.ts";
import { dnsLookup } from "./recon.ts";
import { httpFetch } from "./fetch.ts";
import { scanFile } from "./filescan.ts";
import { runCommand } from "./shell.ts";
import { webFingerprint } from "./fingerprint.ts";
import { tlsInspect } from "./tls.ts";
import { dirProbe } from "./dirbust.ts";
import { cveSearch } from "./cve.ts";
import { tcpScan } from "./portscan.ts";
import { httpMethods } from "./httpmethods.ts";
import { corsCheck } from "./cors.ts";
import { subdomainEnum } from "./subdomains.ts";
import { recordFinding } from "./recordFinding.ts";
import {
  sqliProbe,
  xssProbe,
  openRedirectProbe,
  ssrfProbe,
} from "./injection.ts";
import {
  paramDiscover,
  vhostEnum,
  graphqlIntrospect,
  gitExpose,
  cloudStorageCheck,
} from "./discovery.ts";
import { idorProbe, credentialSpray, authBypassProbe } from "./access.ts";
import { jwtInspect } from "./jwt.ts";
import {
  commandInjectionProbe,
  pathTraversalProbe,
  xxeProbe,
} from "./exploitation.ts";
import { sstiProbe } from "./templating.ts";
import { xpathInjectionProbe, ldapInjectionProbe } from "./queryInjection.ts";
import { deserializationProbe } from "./deserialization.ts";
import { oobStart, oobPoll, oobStop } from "./oob.ts";
import {
  sigmaGenerate,
  logTriage,
  dependencyAudit,
  headerHarden,
  iocCheck,
} from "./defense.ts";
import { checkScope } from "../policy/scope.ts";
import { gateAllows } from "../policy/skillGate.ts";

/** Built-in capabilities compiled into the agent, keyed by tool name. */
const BUILTINS: Tool[] = [
  // Recon & analysis.
  dnsLookup,
  httpFetch,
  scanFile,
  runCommand,
  webFingerprint,
  tlsInspect,
  dirProbe,
  cveSearch,
  tcpScan,
  httpMethods,
  corsCheck,
  subdomainEnum,
  recordFinding,
  // Red Team — injection.
  sqliProbe,
  xssProbe,
  openRedirectProbe,
  ssrfProbe,
  commandInjectionProbe,
  pathTraversalProbe,
  xxeProbe,
  sstiProbe,
  xpathInjectionProbe,
  ldapInjectionProbe,
  deserializationProbe,
  // Red Team — discovery.
  paramDiscover,
  vhostEnum,
  graphqlIntrospect,
  gitExpose,
  cloudStorageCheck,
  // Red Team — access & tokens.
  idorProbe,
  credentialSpray,
  jwtInspect,
  authBypassProbe,
  // Red Team — out-of-band confirmation.
  oobStart,
  oobPoll,
  oobStop,
  // Blue Team — detection, forensics, hardening.
  sigmaGenerate,
  logTriage,
  dependencyAudit,
  headerHarden,
  iocCheck,
];

/**
 * Extensions registered at runtime — skill and MCP tools discovered at startup.
 * Kept apart from the built-ins so the compiled tool set stays inspectable, but
 * merged into every lookup below.
 */
const EXTENSIONS: Tool[] = [];

const BY_NAME = new Map<string, Tool>(
  BUILTINS.map((tool) => [tool.name, tool]),
);

/**
 * Register runtime tools (skills, MCP). A name that collides with an existing
 * tool is skipped rather than overriding it, so an extension can never shadow a
 * built-in capability. Returns which names took and which were skipped.
 */
export function registerTools(tools: Tool[]): {
  registered: string[];
  skipped: string[];
} {
  const registered: string[] = [];
  const skipped: string[] = [];
  for (const tool of tools) {
    if (BY_NAME.has(tool.name)) {
      skipped.push(tool.name);
      continue;
    }
    BY_NAME.set(tool.name, tool);
    EXTENSIONS.push(tool);
    registered.push(tool.name);
  }
  return { registered, skipped };
}

/** Built-ins plus any registered extensions. */
function allTools(): Tool[] {
  return [...BUILTINS, ...EXTENSIONS];
}

/**
 * Tool definitions in the shape the Messages API expects. Sorted by name so the
 * serialized tool list is deterministic and does not invalidate the prompt
 * cache between runs.
 */
export function toolSchemas() {
  return allTools()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.schema,
    }));
}

export interface ToolSummary {
  name: string;
  description: string;
  risky: boolean;
}

/** Tool names, descriptions, and gating, sorted by name — for `/tools`. */
export function listTools(): ToolSummary[] {
  return allTools()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((tool) => ({
      name: tool.name,
      description: tool.description,
      risky: tool.risky === true,
    }));
}

/**
 * Execute a tool the model requested. Unknown names and risky actions the
 * operator declines both return an error outcome rather than throwing, so the
 * loop stays alive and the model can adjust.
 */
export async function dispatch(
  name: string,
  input: Record<string, unknown>,
  ctx: ToolContext,
): Promise<ToolOutcome> {
  const tool = BY_NAME.get(name);
  if (!tool) {
    return { content: `Unknown tool: ${name}`, isError: true };
  }

  const scope = ctx.config.scope;
  const verdict = checkScope(name, input, scope);
  if (!verdict.allowed) {
    return {
      content:
        `Refused: host "${verdict.host}" is outside the configured ` +
        `scope (${scope.join(", ")}).`,
      isError: true,
    };
  }

  if (ctx.skillGate && !gateAllows(ctx.skillGate, name)) {
    return {
      content:
        `Refused: "${name}" is outside the allowed-tools of the active skill ` +
        `"${ctx.skillGate.activeSkill}". Load a skill without an allow-list ` +
        `(or one that permits it) to lift this restriction.`,
      isError: true,
    };
  }

  if (tool.risky) {
    const approved = await ctx.confirm(
      `Tool "${tool.name}" wants to run with: ${JSON.stringify(input)}`,
    );
    if (!approved) {
      return { content: "Operator denied this action.", isError: true };
    }
  }

  try {
    return await tool.run(input, ctx);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { content: `Tool "${name}" failed: ${message}`, isError: true };
  }
}
