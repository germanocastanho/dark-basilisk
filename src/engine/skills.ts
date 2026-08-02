/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Tool } from "../tools/types.ts";
import { safePath } from "../tools/sandbox.ts";
import { listTools } from "../tools/registry.ts";
import { ALWAYS_ALLOWED, applySkillGate } from "../policy/skillGate.ts";

/**
 * A skill is an on-demand playbook: a folder holding a `SKILL.md` whose YAML
 * frontmatter carries a `name` and `description`, and whose body is the full
 * instructions. The catalog (names + descriptions) is injected into context so
 * the model knows what exists; the body is pulled only when `load_skill` runs.
 *
 * Skills use progressive disclosure like Claude Code's: the `SKILL.md` body is
 * the entry point and may reference deeper companion files (`files`), which the
 * agent pulls only when needed with `read_skill_file`.
 */
export interface Skill {
  name: string;
  description: string;
  /** Absolute path to the skill's SKILL.md. */
  path: string;
  /** Absolute path to the skill's directory. */
  dir: string;
  /** Companion file paths, relative to `dir` (excludes SKILL.md). */
  files: string[];
  /**
   * Optional `allowed-tools` from the frontmatter. When present and non-empty,
   * loading the skill restricts the agent to these tools until another skill is
   * loaded. Absent/empty means the skill imposes no restriction.
   */
  allowedTools?: string[];
}

/** Cap on companion files listed per skill, guarding against pathological dirs. */
const MAX_COMPANIONS = 50;

/** Cap on a single companion file's returned size, in characters. */
const MAX_SKILL_FILE_CHARS = 100_000;

/** Writable user skills directory (XDG data dir by default). */
export function skillsDir(): string {
  const base = process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share");
  const dir = join(base, "basilisk", "skills");
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Read-only skills that ship inside the repo (`<root>/skills`). */
export function bundledSkillsDir(): string {
  return join(import.meta.dir, "..", "..", "skills");
}

interface Frontmatter {
  name?: string;
  description?: string;
  allowedTools?: string[];
}

const unquote = (s: string): string => s.replace(/^["']|["']$/g, "").trim();

/**
 * Pull `name`, `description`, and `allowed-tools` from a leading `---`…`---`
 * frontmatter block. Deliberately tiny: a line-scanner for known keys, not a
 * full YAML parser, so skills carry no parsing dependency and a stray field
 * never breaks discovery. Handles YAML block scalars (`>`, `|`, with `+`/`-`
 * chomping) for the folded `description`, and both inline (`[a, b]`) and block
 * (`- a`) sequences for `allowed-tools`.
 */
function parseFrontmatter(text: string): Frontmatter {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return {};
  const lines = match[1]!.split(/\r?\n/);
  const out: Frontmatter = {};
  for (let i = 0; i < lines.length; i++) {
    const kv = lines[i]!.match(/^(name|description|allowed-tools):[ \t]*(.*)$/);
    if (!kv) continue;
    const indicator = kv[2]!.trim();

    if (kv[1] === "allowed-tools") {
      let items: string[];
      if (indicator === "") {
        // Block sequence: gather the indented `- item` lines that follow.
        items = [];
        while (i + 1 < lines.length && /^[ \t]*-[ \t]+/.test(lines[i + 1]!)) {
          items.push(lines[++i]!.replace(/^[ \t]*-[ \t]+/, ""));
        }
      } else {
        // Inline sequence, with or without brackets: `[a, b]` or `a, b`.
        items = indicator.replace(/^\[|\]$/g, "").split(",");
      }
      const tools = items.map(unquote).filter(Boolean);
      if (tools.length > 0) out.allowedTools = tools;
      continue;
    }

    let value: string;
    if (/^[|>][+-]?$/.test(indicator) || indicator === "") {
      // Block scalar (or an empty value): gather the indented lines that follow.
      const parts: string[] = [];
      while (i + 1 < lines.length && /^[ \t]/.test(lines[i + 1]!)) {
        parts.push(lines[++i]!.trim());
      }
      // Folded (`>`) and plain join on spaces; literal (`|`) keeps newlines.
      value = indicator.startsWith("|") ? parts.join("\n") : parts.join(" ");
    } else {
      value = indicator.replace(/^["']|["']$/g, "");
    }
    value = value.trim();
    if (kv[1] === "name") out.name = value;
    else out.description = value;
  }
  return out;
}

/** The instructions body — everything after the frontmatter block. */
function skillBody(text: string): string {
  const stripped = text.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, "");
  return stripped.trim();
}

/**
 * Companion files of a skill: every file under its directory except the
 * top-level SKILL.md, as paths relative to the directory. Walks nested folders
 * (e.g. `references/`, `scripts/`) up to a bounded count.
 */
function listCompanions(dir: string): string[] {
  const out: string[] = [];
  const walk = (rel: string): void => {
    if (out.length >= MAX_COMPANIONS) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(join(dir, rel), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_COMPANIONS) return;
      const childRel = rel ? join(rel, entry.name) : entry.name;
      if (entry.isDirectory()) walk(childRel);
      else if (entry.isFile() && childRel !== "SKILL.md") out.push(childRel);
    }
  };
  walk("");
  return out.sort();
}

/**
 * Scan one directory for skills: each subdirectory with a `SKILL.md` that
 * declares a name and description. Unreadable or unnamed entries are skipped
 * rather than aborting discovery. A missing directory yields nothing.
 */
export function scanSkillsIn(dir: string): Skill[] {
  const skills: Skill[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  for (const entry of entries) {
    const skillDir = join(dir, entry);
    const path = join(skillDir, "SKILL.md");
    let raw: string;
    try {
      raw = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    const { name, description, allowedTools } = parseFrontmatter(raw);
    if (!name || !description) continue;
    skills.push({
      name,
      description,
      path,
      dir: skillDir,
      files: listCompanions(skillDir),
      allowedTools,
    });
  }
  return skills;
}

/**
 * Discover skills from the repo-bundled directory and the user's XDG directory.
 * A user skill overrides a bundled one of the same name, so operators can shadow
 * or update a shipped playbook. Sorted by name for stable catalog output.
 */
export function discoverSkills(): Skill[] {
  const byName = new Map<string, Skill>();
  for (const skill of scanSkillsIn(bundledSkillsDir())) {
    byName.set(skill.name, skill);
  }
  for (const skill of scanSkillsIn(skillsDir())) {
    byName.set(skill.name, skill);
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** A context block advertising the available skills, or null if there are none. */
export function skillsCatalog(skills: Skill[]): string | null {
  if (skills.length === 0) return null;
  const lines = skills.map((s) => `- ${s.name} — ${s.description}`);
  return (
    "### AVAILABLE SKILLS\n\n" +
    "On-demand playbooks are installed. Read the full instructions of one " +
    "with load_skill(name) before applying it; do not act on the summary " +
    "alone.\n\n" +
    lines.join("\n")
  );
}

/**
 * Build the `load_skill` tool bound to the discovered skills. Reading a local,
 * operator-installed playbook neither reaches the target nor changes host state,
 * so it is not gated.
 */
export function loadSkillTool(skills: Skill[]): Tool {
  const byName = new Map(skills.map((s) => [s.name, s]));
  return {
    name: "load_skill",
    description:
      "Read the full instructions of an installed skill by name. Call this " +
      "before applying a skill listed in AVAILABLE SKILLS.",
    schema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Skill name, exactly as listed in AVAILABLE SKILLS.",
          enum: skills.map((s) => s.name),
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
    async run(input, ctx) {
      const name = input.name;
      if (typeof name !== "string") {
        return { content: "Missing skill name.", isError: true };
      }
      const skill = byName.get(name);
      if (!skill) {
        const known = skills.map((s) => s.name).join(", ") || "(none)";
        return {
          content: `Unknown skill "${name}". Installed: ${known}.`,
          isError: true,
        };
      }
      let body: string;
      try {
        body = skillBody(readFileSync(skill.path, "utf8"));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { content: `Failed to read skill: ${message}`, isError: true };
      }

      // Loading a skill re-evaluates the active tool restriction: this skill's
      // allow-list takes effect, or any prior restriction lifts.
      if (ctx.skillGate) {
        applySkillGate(ctx.skillGate, skill.name, skill.allowedTools);
      }

      const files =
        skill.files.length > 0
          ? "\n\n---\nReference files (read on demand with " +
            `read_skill_file("${skill.name}", <path>)):\n` +
            skill.files.map((f) => `- ${f}`).join("\n")
          : "";
      const restriction = restrictionNotice(skill);
      return {
        content: `# Skill: ${skill.name}\n\n${body}${files}${restriction}`,
      };
    },
  };
}

/** The tool-restriction note appended to a loaded skill, or "" when none. */
function restrictionNotice(skill: Skill): string {
  if (!skill.allowedTools || skill.allowedTools.length === 0) return "";
  const known = new Set(listTools().map((t) => t.name));
  const unknown = skill.allowedTools.filter((t) => !known.has(t));
  const always = [...ALWAYS_ALLOWED].join(", ");
  let note =
    "\n\n---\nACTIVE TOOL RESTRICTION: while this skill governs, tool use is " +
    `limited to: ${skill.allowedTools.join(", ")} (plus ${always}). ` +
    "Loading another skill without an allow-list lifts it.";
  if (unknown.length > 0) {
    note += `\nNote: allow-list names not in the registry: ${unknown.join(", ")}.`;
  }
  return note;
}

/**
 * Build the `read_skill_file` tool: pull a skill's companion reference file
 * (progressive disclosure). Reads are confined to the named skill's directory —
 * the path must be one the skill actually ships, and `safePath` blocks any
 * traversal escape. A local read, so it is not gated.
 */
export function readSkillFileTool(skills: Skill[]): Tool {
  const byName = new Map(skills.map((s) => [s.name, s]));
  const withFiles = skills.filter((s) => s.files.length > 0);
  return {
    name: "read_skill_file",
    description:
      "Read a companion reference file of a skill, as listed by load_skill. " +
      "Use for the deeper detail a skill defers to separate files.",
    schema: {
      type: "object",
      properties: {
        skill: {
          type: "string",
          description: "Skill name that owns the file.",
          enum: withFiles.map((s) => s.name),
        },
        path: {
          type: "string",
          description: "File path exactly as listed by load_skill.",
        },
      },
      required: ["skill", "path"],
      additionalProperties: false,
    },
    async run(input) {
      const { skill: skillName, path: rel } = input;
      if (typeof skillName !== "string" || typeof rel !== "string") {
        return { content: "Missing skill or path.", isError: true };
      }
      const skill = byName.get(skillName);
      if (!skill) {
        return { content: `Unknown skill "${skillName}".`, isError: true };
      }
      if (!skill.files.includes(rel)) {
        const known = skill.files.join(", ") || "(none)";
        return {
          content: `"${rel}" is not a file of "${skillName}". Available: ${known}.`,
          isError: true,
        };
      }
      const abs = safePath(skill.dir, rel);
      if (!abs) {
        return { content: "Path escapes the skill directory.", isError: true };
      }
      try {
        let text = readFileSync(abs, "utf8");
        if (text.length > MAX_SKILL_FILE_CHARS) {
          text = `${text.slice(0, MAX_SKILL_FILE_CHARS)}\n\n[truncated]`;
        }
        return { content: `# ${skillName} / ${rel}\n\n${text}` };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { content: `Failed to read file: ${message}`, isError: true };
      }
    },
  };
}
