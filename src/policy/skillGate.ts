/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Tools that stay usable no matter which skill's allow-list is active. The skill
 * navigation tools must never be locked out (or the agent could not switch or
 * lift a restriction), and recording a finding is core to every workflow.
 */
export const ALWAYS_ALLOWED: Set<string> = new Set([
  "load_skill",
  "read_skill_file",
  "record_finding",
]);

/**
 * Per-session tool restriction driven by a skill's `allowed-tools`. Loading a
 * skill that declares an allow-list sets `allowed` to its tool set; loading a
 * skill without one clears it. `null` means unrestricted (the default).
 */
export interface SkillGate {
  activeSkill: string | null;
  allowed: Set<string> | null;
}

/** A fresh, unrestricted gate for a new session. */
export function createSkillGate(): SkillGate {
  return { activeSkill: null, allowed: null };
}

/**
 * Apply a just-loaded skill's restriction, or lift any restriction when the
 * skill declares no (non-empty) allow-list. This is how a restriction both
 * begins and ends: the most recently loaded skill governs.
 */
export function applySkillGate(
  gate: SkillGate,
  skill: string,
  allowedTools: string[] | undefined,
): void {
  if (allowedTools && allowedTools.length > 0) {
    gate.activeSkill = skill;
    gate.allowed = new Set(allowedTools);
  } else {
    gate.activeSkill = null;
    gate.allowed = null;
  }
}

/** Whether the active restriction (if any) permits a tool by name. */
export function gateAllows(gate: SkillGate, toolName: string): boolean {
  if (!gate.allowed) return true;
  if (ALWAYS_ALLOWED.has(toolName)) return true;
  return gate.allowed.has(toolName);
}
