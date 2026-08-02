/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, sep } from "node:path";

/** Directory holding named wordlists, under the XDG config home. */
export function wordlistsDir(): string {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "basilisk", "wordlists");
}

/**
 * Load a wordlist by bare name (resolved under `wordlistsDir`) or by path
 * (relative or absolute). Strips comments and blanks, dedupes preserving
 * first-seen order, and caps to `cap`. Throws if the file is unreadable;
 * returns `[]` when the file yields no usable entries.
 */
export function loadWordlist(nameOrPath: string, cap: number): string[] {
  const hasSeparator =
    isAbsolute(nameOrPath) ||
    nameOrPath.includes(sep) ||
    nameOrPath.includes("/");
  const file = hasSeparator ? nameOrPath : join(wordlistsDir(), nameOrPath);

  let raw: string;
  try {
    raw = readFileSync(file, "utf8");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read wordlist "${file}": ${reason}`);
  }

  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const entry = line.trim();
    if (entry === "" || entry.startsWith("#")) continue;
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
    if (out.length >= cap) break;
  }
  return out;
}
