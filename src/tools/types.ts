/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Config } from "../engine/config.ts";
import type { FindingsStore } from "../engine/findings.ts";
import type { SkillGate } from "../policy/skillGate.ts";
import type { OperatorDirectives } from "../policy/directives.ts";

/**
 * Outcome of a single tool invocation. `content` is fed back to the model as a
 * tool_result block; `isError` maps to the tool_result `is_error` flag so the
 * model can recover instead of treating a failure as a valid answer.
 */
export interface ToolOutcome {
  content: string;
  isError?: boolean;
}

/**
 * Ambient services handed to every tool at call time. Kept minimal on purpose:
 * a tool asks for human sign-off through `confirm` and never touches stdin or
 * the approval policy directly.
 */
export interface ToolContext {
  /** Working root every filesystem tool must stay inside. */
  readonly workdir: string;
  /** Ask the operator to approve a risky action. Returns false on denial. */
  confirm(description: string): Promise<boolean>;
  /** Operator-tunable settings resolved at startup. */
  readonly config: Config;
  /** Sink for structured findings, persisted beside the transcript. */
  readonly findings: FindingsStore;
  /**
   * Active skill tool-restriction, mutated by `load_skill`. Absent means no
   * enforcement (the tool set is never gated by a skill).
   */
  readonly skillGate?: SkillGate;
  /**
   * Operator-stated instructions for the session. Absent means none were
   * given (the tool set is never gated by a directive).
   */
  readonly directives?: OperatorDirectives;
}

/**
 * A capability the model can invoke. `schema` is a raw JSON Schema object — the
 * manual loop forwards it to the Messages API untouched.
 */
export interface Tool {
  readonly name: string;
  readonly description: string;
  readonly schema: { type: "object" } & Record<string, unknown>;
  /**
   * When true, the dispatcher requires operator approval before `run` executes.
   * Use it for anything that reaches out to a target or changes host state.
   */
  readonly risky?: boolean;
  run(input: Record<string, unknown>, ctx: ToolContext): Promise<ToolOutcome>;
}
