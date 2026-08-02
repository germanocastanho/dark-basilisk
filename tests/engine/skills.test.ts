/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  discoverSkills,
  loadSkillTool,
  readSkillFileTool,
  scanSkillsIn,
  skillsCatalog,
  skillsDir,
} from "../../src/engine/skills.ts";
import { createSkillGate } from "../../src/policy/skillGate.ts";
import type { ToolContext } from "../../src/tools/types.ts";

const ctx = {} as ToolContext;

/** Write a companion file inside a skill folder at the active skills dir. */
function writeSkillFile(name: string, rel: string, body: string): void {
  const path = join(skillsDir(), name, rel);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, body);
}

/** Write a skill folder with a SKILL.md at the active skills dir. */
function writeSkill(name: string, body: string): void {
  const dir = join(skillsDir(), name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "SKILL.md"), body);
}

describe("skills", () => {
  let base: string;
  const prev = process.env.XDG_DATA_HOME;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "basilisk-skills-"));
    process.env.XDG_DATA_HOME = base;
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.XDG_DATA_HOME;
    else process.env.XDG_DATA_HOME = prev;
    rmSync(base, { recursive: true, force: true });
  });

  test("skillsDir honours XDG_DATA_HOME", () => {
    expect(skillsDir()).toBe(join(base, "basilisk", "skills"));
  });

  test("an empty user dir scans nothing and yields no catalog", () => {
    expect(scanSkillsIn(skillsDir())).toEqual([]);
    expect(skillsCatalog([])).toBeNull();
  });

  test("scanSkillsIn discovers well-formed skills, skips unnamed ones", () => {
    writeSkill(
      "web-triage",
      "---\nname: web-triage\ndescription: Triage a web target\n---\n\nStep 1.",
    );
    writeSkill("broken", "---\ndescription: no name here\n---\nbody");
    const skills = scanSkillsIn(skillsDir());
    expect(skills).toHaveLength(1);
    expect(skills[0]!.name).toBe("web-triage");
    expect(skills[0]!.description).toBe("Triage a web target");
  });

  test("parses a folded YAML block-scalar description", () => {
    writeSkill(
      "folded",
      "---\nname: folded\ndescription: >-\n  First line of the summary\n" +
        "  and its continuation.\n---\n\nbody",
    );
    const skills = scanSkillsIn(skillsDir());
    expect(skills[0]!.description).toBe(
      "First line of the summary and its continuation.",
    );
  });

  test("catalog lists each skill's name and description", () => {
    writeSkill(
      "auth-check",
      "---\nname: auth-check\ndescription: Audit auth\n---\nbody",
    );
    const catalog = skillsCatalog(scanSkillsIn(skillsDir()));
    expect(catalog).toContain("AVAILABLE SKILLS");
    expect(catalog).toContain("auth-check — Audit auth");
  });

  test("load_skill returns the body without frontmatter", async () => {
    writeSkill(
      "web-triage",
      "---\nname: web-triage\ndescription: d\n---\n\nDo the thing.",
    );
    const tool = loadSkillTool(scanSkillsIn(skillsDir()));
    const out = await tool.run({ name: "web-triage" }, ctx);
    expect(out.isError).toBeFalsy();
    expect(out.content).toContain("Do the thing.");
    expect(out.content).not.toContain("description: d");
  });

  test("load_skill errors on an unknown name", async () => {
    writeSkill("known", "---\nname: known\ndescription: d\n---\nbody");
    const tool = loadSkillTool(scanSkillsIn(skillsDir()));
    const out = await tool.run({ name: "ghost" }, ctx);
    expect(out.isError).toBe(true);
    expect(out.content).toContain("Unknown skill");
  });

  test("bundled repo skills are discovered and all parse cleanly", () => {
    // XDG is an empty temp dir here, so this is the bundled set only.
    const skills = discoverSkills();
    expect(skills.length).toBeGreaterThanOrEqual(20);
    for (const s of skills) {
      expect(s.name).toMatch(/^[a-z0-9-]+$/);
      expect(s.description.length).toBeGreaterThan(20);
      expect(s.description).not.toContain(">-");
    }
    expect(skills.map((s) => s.name)).toContain("recon-and-methodology");
  });

  test("a user skill overrides a bundled skill of the same name", () => {
    writeSkill(
      "recon-and-methodology",
      "---\nname: recon-and-methodology\ndescription: my override\n---\nmine",
    );
    const skill = discoverSkills().find(
      (s) => s.name === "recon-and-methodology",
    );
    expect(skill!.description).toBe("my override");
    expect(skill!.path).toContain(base);
  });

  test("companion files are enumerated and load_skill advertises them", async () => {
    writeSkill("multi", "---\nname: multi\ndescription: has refs\n---\nbody");
    writeSkillFile("multi", "REF.md", "deep detail here");
    const skill = scanSkillsIn(skillsDir())[0]!;
    expect(skill.files).toEqual(["REF.md"]);
    const out = await loadSkillTool([skill]).run({ name: "multi" }, ctx);
    expect(out.content).toContain("read_skill_file");
    expect(out.content).toContain("- REF.md");
  });

  test("read_skill_file returns a listed companion file", async () => {
    writeSkill("multi", "---\nname: multi\ndescription: has refs\n---\nbody");
    writeSkillFile("multi", "REF.md", "deep detail here");
    const tool = readSkillFileTool(scanSkillsIn(skillsDir()));
    const out = await tool.run({ skill: "multi", path: "REF.md" }, ctx);
    expect(out.isError).toBeFalsy();
    expect(out.content).toContain("deep detail here");
  });

  test("read_skill_file rejects an unlisted path and traversal", async () => {
    writeSkill("multi", "---\nname: multi\ndescription: has refs\n---\nbody");
    writeSkillFile("multi", "REF.md", "deep detail here");
    const tool = readSkillFileTool(scanSkillsIn(skillsDir()));
    const unlisted = await tool.run({ skill: "multi", path: "secret" }, ctx);
    expect(unlisted.isError).toBe(true);
    const escape = await tool.run(
      { skill: "multi", path: "../../etc/passwd" },
      ctx,
    );
    expect(escape.isError).toBe(true);
  });

  test("allowed-tools parses block, inline-bracket, and comma forms", () => {
    writeSkill(
      "block",
      "---\nname: block\ndescription: d\nallowed-tools:\n  - dns_lookup\n" +
        "  - cve_search\n---\nx",
    );
    writeSkill(
      "inline",
      "---\nname: inline\ndescription: d\nallowed-tools: [dns_lookup, cve_search]\n---\nx",
    );
    writeSkill(
      "comma",
      "---\nname: comma\ndescription: d\nallowed-tools: dns_lookup, cve_search\n---\nx",
    );
    writeSkill("none", "---\nname: none\ndescription: d\n---\nx");
    const byName = new Map(
      scanSkillsIn(skillsDir()).map((s) => [s.name, s.allowedTools]),
    );
    expect(byName.get("block")).toEqual(["dns_lookup", "cve_search"]);
    expect(byName.get("inline")).toEqual(["dns_lookup", "cve_search"]);
    expect(byName.get("comma")).toEqual(["dns_lookup", "cve_search"]);
    expect(byName.get("none")).toBeUndefined();
  });

  test("load_skill applies the tool restriction, and an open skill lifts it", async () => {
    writeSkill(
      "locked",
      "---\nname: locked\ndescription: d\nallowed-tools: [dns_lookup]\n---\nx",
    );
    writeSkill("open", "---\nname: open\ndescription: d\n---\nx");
    const gate = createSkillGate();
    const gctx = { ...ctx, skillGate: gate } as ToolContext;
    const tool = loadSkillTool(scanSkillsIn(skillsDir()));

    const locked = await tool.run({ name: "locked" }, gctx);
    expect(locked.content).toContain("ACTIVE TOOL RESTRICTION");
    expect(gate.activeSkill).toBe("locked");
    expect([...(gate.allowed ?? [])]).toEqual(["dns_lookup"]);

    await tool.run({ name: "open" }, gctx);
    expect(gate.activeSkill).toBeNull();
    expect(gate.allowed).toBeNull();
  });
});
