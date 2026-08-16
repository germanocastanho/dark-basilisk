/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * ASCII wordmark for the agent, shown at the top of the REPL. Kept as plain
 * lines (no ANSI) so the Ink app can colorize them with a Text prop.
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
export const BANNER_TAGLINE = "🐍 DARK BASILISK · Cybersecurity agent";
