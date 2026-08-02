/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Resolved API-key credential the client authenticates with. Basilisk speaks to
 * the Anthropic API only, and only via an API key — there is no OAuth or Claude
 * Code login path.
 */
export interface ResolvedAuth {
  apiKey: string;
  /** Where the key came from, for diagnostics. */
  source: string;
}

/**
 * Read the Anthropic API key from the environment. Throws a descriptive error
 * when `ANTHROPIC_API_KEY` is absent or blank, so the CLI can surface a clean
 * message instead of a deep SDK failure.
 */
export function resolveAuth(): ResolvedAuth {
  const apiKey = process.env.ANTHROPIC_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      "No API key found. Set ANTHROPIC_API_KEY in the environment " +
        "(get one at https://console.anthropic.com/).",
    );
  }
  return { apiKey, source: "ANTHROPIC_API_KEY" };
}
