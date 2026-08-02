/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { resolve, relative, isAbsolute } from "node:path";

/**
 * Resolve a model-supplied path and confirm it stays inside the working root.
 * Rejects `..` traversal and absolute-path escapes before any read happens, so
 * a tool cannot name a file outside the working directory. (Symlinks within the
 * root are followed by the read; the sandbox assumes a trusted workdir.)
 * Returns the absolute path, or null when the candidate escapes the root.
 */
export function safePath(workdir: string, candidate: string): string | null {
  const root = resolve(workdir);
  const target = resolve(root, candidate);
  const rel = relative(root, target);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return null;
  }
  return target;
}
