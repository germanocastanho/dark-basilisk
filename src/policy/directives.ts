/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Operator-stated instructions for the current session: free-form notes the
 * model is told to follow, plus tools mechanically denied regardless of what
 * the model decides. Both are append-only for the session — set via
 * `--instruct`/`--deny-tool` at startup or `/instruct`/`/deny` in chat.
 */
export interface OperatorDirectives {
  notes: string[];
  deniedTools: Set<string>;
}

/** A fresh, empty directive set for a new session. */
export function createDirectives(): OperatorDirectives {
  return { notes: [], deniedTools: new Set() };
}

/** Record a free-text instruction the model should follow this session. */
export function addNote(directives: OperatorDirectives, text: string): void {
  const trimmed = text.trim();
  if (trimmed) directives.notes.push(trimmed);
}

/** Forbid a tool by name for the rest of the session. */
export function denyTool(directives: OperatorDirectives, name: string): void {
  directives.deniedTools.add(name.trim());
}

/** Whether a tool is mechanically denied by the operator's directives. */
export function toolDenied(
  directives: OperatorDirectives | undefined,
  name: string,
): boolean {
  return directives?.deniedTools.has(name) ?? false;
}

/**
 * Render the session's directives as a system-prompt block, or undefined
 * when there is nothing to say — so the caller can skip the block entirely.
 */
export function formatDirectives(
  directives: OperatorDirectives,
): string | undefined {
  if (directives.notes.length === 0 && directives.deniedTools.size === 0) {
    return undefined;
  }
  const lines = ["OPERATOR DIRECTIVES — follow exactly for this session:"];
  for (const note of directives.notes) lines.push(`- ${note}`);
  if (directives.deniedTools.size > 0) {
    lines.push(
      `- Do not call: ${[...directives.deniedTools].join(", ")} ` +
        "(mechanically refused if attempted).",
    );
  }
  return lines.join("\n");
}
