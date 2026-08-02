/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { colors } from "./stream.ts";

/**
 * ASCII wordmark for the agent, shown at the top of the REPL and headless runs.
 * Kept as plain lines (no ANSI) so the Ink app can colorize them with a Text
 * prop; `printBanner` adds color for the plain-stdout paths.
 */
export const BANNER_LINES: string[] = [

            "██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗",
            "██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝",
            "██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ ",
            "██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ ",
            "██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗",
            "╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝",

          ];

/** One-line identity shown beneath the wordmark. */
export const BANNER_TAGLINE =
  "🐍 DARK BASILISK · Cybersecurity agent";

/** Green-colored banner block for the plain-stdout (non-Ink) commands. */
export function printBanner(): string {
  const art = BANNER_LINES.map((line) => colors.green(line)).join("\n");
  return `${art}\n${colors.dim(BANNER_TAGLINE)}\n\n`;
}
