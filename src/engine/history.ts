/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";

type Message = Anthropic.MessageParam;

interface StoredSession {
  version: 1;
  id: string;
  createdAt: string;
  updatedAt: string;
  messages: Message[];
}

/** Directory where session transcripts live (XDG state dir by default). */
export function sessionsDir(): string {
  const base = process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state");
  const dir = join(base, "basilisk", "sessions");
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Path for a brand-new session, named by a sortable timestamp id. */
export function newSessionPath(): string {
  const id = new Date().toISOString().replace(/[:.]/g, "-");
  return join(sessionsDir(), `${id}.json`);
}

/**
 * Persist the full conversation to disk. Called after every turn so a crash or
 * Ctrl+C never loses the transcript. Thinking and tool blocks are stored
 * verbatim so a resumed session replays correctly on the same model.
 */
export function saveSession(path: string, messages: Message[]): void {
  const id = basename(path).replace(/\.json$/, "") || "session";
  const now = new Date().toISOString();
  let createdAt = now;
  try {
    const existing = JSON.parse(readFileSync(path, "utf8")) as StoredSession;
    if (existing.createdAt) createdAt = existing.createdAt;
  } catch {
    // First write for this session — keep `now` as createdAt.
  }
  const doc: StoredSession = {
    version: 1,
    id,
    createdAt,
    updatedAt: now,
    messages,
  };
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
}

/** Load a previously saved session's messages for resuming. */
export function loadSession(path: string): Message[] {
  const doc = JSON.parse(readFileSync(path, "utf8")) as StoredSession;
  if (!Array.isArray(doc.messages)) {
    throw new Error(`${path} is not a valid session file.`);
  }
  return doc.messages;
}

export interface SessionSummary {
  path: string;
  updatedAt: string;
  turns: number;
}

/** List saved sessions, most recently updated first. */
export function listSessions(): SessionSummary[] {
  const dir = sessionsDir();
  const summaries: SessionSummary[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const path = join(dir, name);
    try {
      const doc = JSON.parse(readFileSync(path, "utf8")) as StoredSession;
      summaries.push({
        path,
        updatedAt: doc.updatedAt ?? statSync(path).mtime.toISOString(),
        turns: Array.isArray(doc.messages) ? doc.messages.length : 0,
      });
    } catch {
      // Skip unreadable/corrupt files rather than aborting the listing.
    }
  }
  return summaries.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}
