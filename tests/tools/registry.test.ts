/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { describe, expect, test } from "bun:test";
import {
  dispatch,
  listTools,
  registerTools,
} from "../../src/tools/registry.ts";
import type { Tool, ToolContext } from "../../src/tools/types.ts";
import type { SkillGate } from "../../src/policy/skillGate.ts";
import { createDirectives, denyTool } from "../../src/policy/directives.ts";
import type { Config } from "../../src/engine/config.ts";
import type { Finding, FindingsStore } from "../../src/engine/findings.ts";
import { DEFAULT_MODEL } from "../../src/engine/model.ts";

const noopFindings: FindingsStore = {
  path: "/dev/null",
  list: () => [],
  record: (input) => ({ id: "F-1", createdAt: "", ...input }) as Finding,
};

/** Build a ToolContext with a configurable scope and confirm spy. */
function makeCtx(scope: string[], confirm: () => boolean) {
  let confirmCalls = 0;
  const config: Config = {
    model: DEFAULT_MODEL,
    commandTimeoutMs: 1000,
    allowedCommands: [],
    scope,
    mcpServers: [],
  };
  const ctx: ToolContext = {
    workdir: "/tmp",
    confirm: async () => {
      confirmCalls += 1;
      return confirm();
    },
    config,
    findings: noopFindings,
  };
  return { ctx, calls: () => confirmCalls };
}

describe("dispatch", () => {
  test("reports an unknown tool as an error", async () => {
    const { ctx } = makeCtx([], () => true);
    const out = await dispatch("does_not_exist", {}, ctx);
    expect(out.isError).toBe(true);
    expect(out.content).toContain("Unknown tool");
  });

  test("refuses an out-of-scope target before prompting", async () => {
    const { ctx, calls } = makeCtx(["example.com"], () => true);
    const out = await dispatch(
      "http_fetch",
      { url: "https://evil.example/" },
      ctx,
    );
    expect(out.isError).toBe(true);
    expect(out.content).toContain("outside the configured scope");
    // Scope is enforced before the approval gate — confirm must not run.
    expect(calls()).toBe(0);
  });

  test("returns a denial when the operator says no", async () => {
    const { ctx, calls } = makeCtx([], () => false);
    const out = await dispatch(
      "http_fetch",
      { url: "https://target.example/" },
      ctx,
    );
    expect(out.isError).toBe(true);
    expect(out.content).toContain("Operator denied");
    expect(calls()).toBe(1);
  });

  test("refuses a tool denied by an operator directive", async () => {
    const { ctx, calls } = makeCtx([], () => true);
    const directives = createDirectives();
    denyTool(directives, "http_fetch");
    const out = await dispatch(
      "http_fetch",
      { url: "https://target.example/" },
      { ...ctx, directives },
    );
    expect(out.isError).toBe(true);
    expect(out.content).toContain("denied by an operator directive");
    expect(calls()).toBe(0);
  });
});

describe("registerTools", () => {
  const makeTool = (name: string): Tool => ({
    name,
    description: "ext",
    schema: { type: "object", properties: {}, additionalProperties: false },
    run: async () => ({ content: `ran ${name}` }),
  });

  test("registers a new tool so it dispatches and lists", async () => {
    const result = registerTools([makeTool("ext_probe")]);
    expect(result.registered).toEqual(["ext_probe"]);
    expect(listTools().some((t) => t.name === "ext_probe")).toBe(true);
    const { ctx } = makeCtx([], () => true);
    const out = await dispatch("ext_probe", {}, ctx);
    expect(out.content).toBe("ran ext_probe");
  });

  test("skips a name that collides with a built-in", () => {
    const result = registerTools([makeTool("http_fetch")]);
    expect(result.skipped).toEqual(["http_fetch"]);
    expect(result.registered).toEqual([]);
  });
});

describe("dispatch skill gate", () => {
  const withGate = (gate: SkillGate): ToolContext => ({
    ...makeCtx([], () => true).ctx,
    skillGate: gate,
  });

  test("refuses a tool outside the active skill's allow-list", async () => {
    registerTools([makeGateTool("gate_probe")]);
    const ctx = withGate({
      activeSkill: "locked",
      allowed: new Set(["dns_lookup"]),
    });
    const out = await dispatch("gate_probe", {}, ctx);
    expect(out.isError).toBe(true);
    expect(out.content).toContain("outside the allowed-tools");
  });

  test("allows a tool inside the allow-list and any meta-tool", async () => {
    registerTools([makeGateTool("gate_allowed")]);
    const ctx = withGate({
      activeSkill: "locked",
      allowed: new Set(["gate_allowed"]),
    });
    expect((await dispatch("gate_allowed", {}, ctx)).content).toBe(
      "ran gate_allowed",
    );
    // record_finding is exempt even though it is not in the allow-list.
    const finding = await dispatch("record_finding", {}, ctx);
    expect(finding.content).not.toContain("outside the allowed-tools");
  });

  test("an unrestricted gate blocks nothing", async () => {
    registerTools([makeGateTool("gate_free")]);
    const ctx = withGate({ activeSkill: null, allowed: null });
    expect((await dispatch("gate_free", {}, ctx)).content).toBe(
      "ran gate_free",
    );
  });
});

/** A non-risky extension tool used to exercise the skill gate. */
function makeGateTool(name: string): Tool {
  return {
    name,
    description: "gate",
    schema: { type: "object", properties: {}, additionalProperties: false },
    run: async () => ({ content: `ran ${name}` }),
  };
}
