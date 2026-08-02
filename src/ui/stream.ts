/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Tiny ANSI helpers so the v0 stdout interface stays dependency-free. Color is
 * suppressed when stdout is not a TTY or NO_COLOR is set, keeping piped output
 * clean.
 */
const enabled = process.stdout.isTTY === true && !process.env.NO_COLOR;

function wrap(open: string, close: string) {
  return (text: string): string => (enabled ? `${open}${text}${close}` : text);
}

export const colors = {
  dim: wrap("\x1b[2m", "\x1b[0m"),
  bold: wrap("\x1b[1m", "\x1b[0m"),
  warn: wrap("\x1b[33m", "\x1b[0m"),
  error: wrap("\x1b[31m", "\x1b[0m"),
  accent: wrap("\x1b[36m", "\x1b[0m"),
  green: wrap("\x1b[32m", "\x1b[0m"),
};

export function write(text: string): void {
  process.stdout.write(text);
}
