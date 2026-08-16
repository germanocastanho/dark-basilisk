/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import Anthropic from "@anthropic-ai/sdk";
import { DEFAULT_MODEL, type ModelConfig } from "./model.ts";
import { SYSTEM_PROMPT } from "./systemPrompt.ts";
import { dispatch, toolSchemas } from "../tools/registry.ts";
import type { ToolContext } from "../tools/types.ts";

type Message = Anthropic.MessageParam;

/**
 * Everything a turn wants to show the operator, emitted as it happens. The loop
 * stays I/O-agnostic — the caller (an Ink UI, a test, a logger) decides how to
 * render each event.
 */
export type TurnEvent =
  | { type: "thinking_start" }
  | { type: "thinking"; text: string }
  | { type: "text"; text: string }
  | { type: "tool"; name: string }
  | { type: "notice"; level: "warn" | "error"; text: string };

/** Fallback wait when a 429 carries no Retry-After hint. */
const DEFAULT_RETRY_MS = 5000;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Retry-After the server asked for, in ms, or null if it gave no usable hint.
 * Mirrors the SDK's own parsing: prefer `retry-after-ms`, then `retry-after`
 * as either delta-seconds or an HTTP date.
 */
export function retryAfterMs(headers: Headers): number | null {
  const ms = headers.get("retry-after-ms");
  if (ms) {
    const n = Number.parseFloat(ms);
    if (!Number.isNaN(n) && n > 0) return n;
  }
  const after = headers.get("retry-after");
  if (after) {
    const seconds = Number.parseFloat(after);
    if (!Number.isNaN(seconds)) return seconds > 0 ? seconds * 1000 : null;
    const delta = Date.parse(after) - Date.now();
    if (!Number.isNaN(delta) && delta > 0) return delta;
  }
  return null;
}

/** Compact human duration: "8s", "2m 30s", "1h 5m". */
export function formatDuration(ms: number): string {
  const total = Math.max(1, Math.round(ms / 1000));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes < 60) return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return remMinutes ? `${hours}h ${remMinutes}m` : `${hours}h`;
}

/**
 * Handle a surfaced 429. Transient limits are already retried by the SDK, so a
 * 429 reaching here is usually plan-usage exhaustion — a decision the operator
 * should make. Ask (through the same gate risky tools use), and on a yes wait
 * the server-suggested time, then signal a retry. Returns false to propagate.
 */
async function askRetryOnRateLimit(
  headers: Headers,
  ctx: ToolContext,
  emit: (event: TurnEvent) => void,
): Promise<boolean> {
  const hint = retryAfterMs(headers);
  const waitMs = hint ?? DEFAULT_RETRY_MS;
  const suggestion =
    hint === null
      ? `No wait hint from the server; would retry in ${formatDuration(waitMs)}`
      : `Server suggests waiting ~${formatDuration(waitMs)}`;
  const ok = await ctx.confirm(
    `Rate limited by the API. ${suggestion} before retrying this turn.`,
  );
  if (!ok) return false;
  emit({
    type: "notice",
    level: "warn",
    text: `Waiting ${formatDuration(waitMs)} before retry…`,
  });
  await sleep(waitMs);
  return true;
}

/**
 * Drive one operator turn to completion. This is a hand-written agent loop
 * rather than the SDK tool runner: a security agent needs an explicit approval
 * gate between the model asking for a tool and the tool running, and owning the
 * loop keeps that boundary in plain sight.
 *
 * The passed `history` is mutated in place and returned so the caller can carry
 * the full conversation into the next turn.
 */
export async function runTurn(
  client: Anthropic,
  history: Message[],
  ctx: ToolContext,
  emit: (event: TurnEvent) => void,
  config: ModelConfig = DEFAULT_MODEL,
  briefing?: string,
  directives?: string,
): Promise<Message[]> {
  // Frozen prompt stays the cached prefix; a session briefing (installed
  // skills, connected MCP servers) and operator directives ride after it as
  // a separate, non-cached block so the no-extension path is byte-identical
  // to before.
  const extra = [briefing, directives].filter(Boolean).join("\n\n");
  const system: string | Anthropic.TextBlockParam[] = extra
    ? [
        {
          type: "text",
          text: SYSTEM_PROMPT,
          cache_control: { type: "ephemeral" },
        },
        { type: "text", text: extra },
      ]
    : SYSTEM_PROMPT;

  for (;;) {
    let message: Anthropic.Message;
    try {
      const stream = client.messages.stream({
        model: config.model,
        max_tokens: config.maxTokens,
        thinking: { type: "adaptive", display: "summarized" },
        system,
        tools: toolSchemas(),
        messages: history,
      });

      // Surface reasoning summaries and answer text as they arrive.
      for await (const event of stream) {
        if (
          event.type === "content_block_start" &&
          event.content_block.type === "thinking"
        ) {
          emit({ type: "thinking_start" });
        } else if (event.type === "content_block_delta") {
          if (event.delta.type === "thinking_delta") {
            emit({ type: "thinking", text: event.delta.thinking });
          } else if (event.delta.type === "text_delta") {
            emit({ type: "text", text: event.delta.text });
          }
        }
      }

      message = await stream.finalMessage();
    } catch (err) {
      // A 429 opens the retry gate; the operator decides. Anything else (and a
      // declined retry) propagates so the caller reverts the turn.
      if (
        err instanceof Anthropic.RateLimitError &&
        (await askRetryOnRateLimit(err.headers, ctx, emit))
      ) {
        continue;
      }
      throw err;
    }

    history.push({ role: "assistant", content: message.content });

    if (message.stop_reason === "refusal") {
      emit({
        type: "notice",
        level: "error",
        text: "[declined for safety reasons]",
      });
      return history;
    }

    if (message.stop_reason === "max_tokens") {
      emit({
        type: "notice",
        level: "warn",
        text: "[response hit the token cap — ask to continue]",
      });
      return history;
    }

    if (message.stop_reason !== "tool_use") {
      return history;
    }

    // Execute every requested tool, then feed all results back in one user turn
    // so parallel tool calls keep working.
    const toolUses = message.content.filter(
      (block): block is Anthropic.ToolUseBlock => block.type === "tool_use",
    );

    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const call of toolUses) {
      const input = (call.input ?? {}) as Record<string, unknown>;
      emit({ type: "tool", name: call.name });
      const outcome = await dispatch(call.name, input, ctx);
      results.push({
        type: "tool_result",
        tool_use_id: call.id,
        content: outcome.content,
        is_error: outcome.isError ?? false,
      });
    }

    history.push({ role: "user", content: results });
  }
}
