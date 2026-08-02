/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import {
  listSessions,
  loadSession,
  newSessionPath,
  saveSession,
  sessionsDir,
} from "../../src/engine/history.ts";

const MSGS: Anthropic.MessageParam[] = [
  { role: "user", content: "hi" },
  { role: "assistant", content: "hello" },
];

describe("history", () => {
  let base: string;
  const prev = process.env.XDG_STATE_HOME;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "basilisk-hist-"));
    process.env.XDG_STATE_HOME = base;
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = prev;
    rmSync(base, { recursive: true, force: true });
  });

  test("newSessionPath sits under the state dir and ends in .json", () => {
    const p = newSessionPath();
    expect(p.startsWith(sessionsDir())).toBe(true);
    expect(p.endsWith(".json")).toBe(true);
  });

  test("save then load round-trips the messages", () => {
    const p = newSessionPath();
    saveSession(p, MSGS);
    expect(loadSession(p)).toEqual(MSGS);
  });

  test("re-saving preserves createdAt but advances updatedAt", () => {
    const p = newSessionPath();
    saveSession(p, MSGS.slice(0, 1));
    const first = JSON.parse(readFileSync(p, "utf8"));
    saveSession(p, MSGS);
    const second = JSON.parse(readFileSync(p, "utf8"));
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt >= first.updatedAt).toBe(true);
    expect(second.messages).toHaveLength(2);
  });

  test("listSessions returns newest-first with turn counts", () => {
    const dir = sessionsDir();
    writeFileSync(
      join(dir, "old.json"),
      JSON.stringify({
        version: 1,
        id: "old",
        createdAt: "x",
        updatedAt: "2026-01-01T00:00:00.000Z",
        messages: [1],
      }),
    );
    writeFileSync(
      join(dir, "new.json"),
      JSON.stringify({
        version: 1,
        id: "new",
        createdAt: "x",
        updatedAt: "2026-02-01T00:00:00.000Z",
        messages: [1, 2, 3],
      }),
    );
    const list = listSessions();
    expect(list).toHaveLength(2);
    expect(list[0]!.path).toBe(join(dir, "new.json"));
    expect(list[0]!.turns).toBe(3);
    expect(list[1]!.turns).toBe(1);
  });

  test("loadSession rejects a file without a messages array", () => {
    const p = join(sessionsDir(), "bad.json");
    writeFileSync(p, JSON.stringify({ version: 1 }));
    expect(() => loadSession(p)).toThrow(/not a valid session/);
  });
});
