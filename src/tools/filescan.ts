/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { readFile } from "node:fs/promises";
import type { Tool } from "./types.ts";
import { safePath } from "./sandbox.ts";

const MAX_FILE_BYTES = 512 * 1024;
const MAX_MATCHES = 200;

/**
 * Read a local file for code and log analysis, optionally filtering to lines
 * that match a regular expression. Read-only within the working root, so no
 * approval gate is needed.
 */
export const scanFile: Tool = {
  name: "scan_file",
  description:
    "Read a local file for code/log analysis, optionally keeping only " +
    "lines matching a regex. Confined to the working directory.",
  schema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Path relative to the working directory.",
      },
      pattern: {
        type: "string",
        description: "Optional JavaScript regular expression to filter lines.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },

  async run(input, ctx) {
    const { path, pattern } = input;
    if (typeof path !== "string") {
      return { content: "Missing path.", isError: true };
    }

    const target = safePath(ctx.workdir, path);
    if (!target) {
      return { content: "Path escapes the working directory.", isError: true };
    }

    let text: string;
    try {
      const bytes = await readFile(target);
      if (bytes.byteLength > MAX_FILE_BYTES) {
        return {
          content:
            `File is ${bytes.byteLength} bytes, over the ` +
            `${MAX_FILE_BYTES}-byte limit. Narrow the read.`,
          isError: true,
        };
      }
      text = bytes.toString("utf8");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: `Cannot read file: ${message}`, isError: true };
    }

    if (typeof pattern !== "string" || pattern.length === 0) {
      return { content: text };
    }

    let regex: RegExp;
    try {
      regex = new RegExp(pattern);
    } catch {
      return { content: "Invalid regular expression.", isError: true };
    }

    const matches: string[] = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      if (regex.test(line)) {
        matches.push(`${i + 1}: ${line}`);
        if (matches.length >= MAX_MATCHES) {
          matches.push(`[stopped at ${MAX_MATCHES} matches]`);
          break;
        }
      }
    }

    return {
      content:
        matches.length > 0
          ? matches.join("\n")
          : `No lines matched /${pattern}/.`,
    };
  },
};
