/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import Anthropic from "@anthropic-ai/sdk";
import { resolveAuth } from "./auth.ts";

/**
 * Model settings for the agent loop. Opus 5 is the default for its agentic and
 * security-reasoning strength; adaptive thinking lets the model decide how much
 * to reason per turn. maxTokens is sized for streaming (well above the
 * non-streaming timeout ceiling).
 */
export interface ModelConfig {
  model: string;
  maxTokens: number;
}

export const DEFAULT_MODEL: ModelConfig = {
  model: "claude-opus-5",
  maxTokens: 64000,
};

/**
 * Build the Anthropic SDK client from the `ANTHROPIC_API_KEY` in the
 * environment. Throws (via `resolveAuth`) when no key is set.
 */
export function createClient(): Anthropic {
  const { apiKey } = resolveAuth();
  return new Anthropic({ apiKey });
}
