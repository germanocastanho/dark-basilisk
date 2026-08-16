/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { registerTools } from "../tools/registry.ts";
import {
  discoverSkills,
  loadSkillTool,
  readSkillFileTool,
  skillsCatalog,
} from "./skills.ts";
import { connectMcpServers, mcpCatalog } from "./mcp.ts";
import type { Config } from "./config.ts";

/**
 * Runtime extensions resolved at startup: on-disk skills and connected MCP
 * servers, both folded into the shared tool registry.
 */
export interface Extensions {
  /** Context block (skills catalog + MCP servers) to ride after the prompt. */
  briefing?: string;
  /** Human status lines for the startup banner. */
  notes: string[];
  /** Tear down MCP connections. Safe to call when nothing was connected. */
  close(): Promise<void>;
}

/**
 * Discover skills and connect MCP servers, register everything with the tool
 * registry, and assemble the session briefing. Failures are surfaced as notes
 * rather than thrown — a broken skill or server degrades the session, it does
 * not abort it.
 */
export async function loadExtensions(config: Config): Promise<Extensions> {
  const notes: string[] = [];
  const blocks: string[] = [];

  const skills = discoverSkills();
  if (skills.length > 0) {
    const skillTools = [loadSkillTool(skills)];
    // Only wire the reference-file reader when a skill actually ships
    // companions.
    if (skills.some((s) => s.files.length > 0)) {
      skillTools.push(readSkillFileTool(skills));
    }
    registerTools(skillTools);
    const catalog = skillsCatalog(skills);
    if (catalog) blocks.push(catalog);
    notes.push(`Skills: ${skills.length} installed.`);
  }

  const mcp = await connectMcpServers(config.mcpServers);
  if (mcp.tools.length > 0) registerTools(mcp.tools);
  const catalog = mcpCatalog(mcp.connected);
  if (catalog) blocks.push(catalog);
  for (const server of mcp.connected) {
    notes.push(`MCP ${server.name}: ${server.toolCount} tools.`);
  }
  for (const failure of mcp.errors) {
    notes.push(`MCP ${failure.name}: failed (${failure.message}).`);
  }

  return {
    briefing: blocks.length > 0 ? blocks.join("\n\n") : undefined,
    notes,
    close: mcp.close,
  };
}
