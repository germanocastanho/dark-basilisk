/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configPath, loadConfig } from "../../src/engine/config.ts";
import { DEFAULT_MODEL } from "../../src/engine/model.ts";

describe("loadConfig", () => {
  let base: string;
  const prev = process.env.XDG_CONFIG_HOME;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "basilisk-cfg-"));
    process.env.XDG_CONFIG_HOME = base;
    mkdirSync(join(base, "basilisk"), { recursive: true });
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = prev;
    rmSync(base, { recursive: true, force: true });
  });

  const writeConfig = (obj: unknown): void =>
    writeFileSync(join(base, "basilisk", "config.json"), JSON.stringify(obj));

  test("configPath honours XDG_CONFIG_HOME", () => {
    expect(configPath()).toBe(join(base, "basilisk", "config.json"));
  });

  test("absent file yields defaults", () => {
    rmSync(join(base, "basilisk"), { recursive: true, force: true });
    const c = loadConfig();
    expect(c.model).toEqual(DEFAULT_MODEL);
    expect(c.commandTimeoutMs).toBe(120_000);
    expect(c.allowedCommands).toEqual([]);
    expect(c.scope).toEqual([]);
  });

  test("a valid config is parsed through", () => {
    writeConfig({
      model: { model: "claude-x", maxTokens: 1000 },
      commandTimeoutMs: 5000,
      allowedCommands: ["ffuf"],
      scope: ["a.example"],
    });
    const c = loadConfig();
    expect(c.model).toEqual({ model: "claude-x", maxTokens: 1000 });
    expect(c.commandTimeoutMs).toBe(5000);
    expect(c.allowedCommands).toEqual(["ffuf"]);
    expect(c.scope).toEqual(["a.example"]);
  });

  test("invalid per-key values fall back individually", () => {
    writeConfig({
      model: { maxTokens: -5 },
      commandTimeoutMs: "nope",
      allowedCommands: [1, "ok", 2],
      scope: "notarray",
    });
    const c = loadConfig();
    expect(c.model.model).toBe(DEFAULT_MODEL.model);
    expect(c.model.maxTokens).toBe(DEFAULT_MODEL.maxTokens);
    expect(c.commandTimeoutMs).toBe(120_000);
    expect(c.allowedCommands).toEqual(["ok"]);
    expect(c.scope).toEqual([]);
  });

  test("malformed JSON falls back to defaults", () => {
    writeFileSync(join(base, "basilisk", "config.json"), "{ not json");
    expect(loadConfig().commandTimeoutMs).toBe(120_000);
  });

  test("absent mcpServers defaults to empty", () => {
    writeConfig({ scope: ["a.example"] });
    expect(loadConfig().mcpServers).toEqual([]);
  });

  test("valid mcpServers entries are parsed, malformed ones dropped", () => {
    writeConfig({
      mcpServers: [
        {
          name: "fs",
          command: "mcp-fs",
          args: ["/tmp", 3],
          env: { A: "1", B: 2 },
        },
        { name: "noCommand" },
        { command: "noName" },
        "notAnObject",
        { name: "bare", command: "run" },
      ],
    });
    expect(loadConfig().mcpServers).toEqual([
      { name: "fs", command: "mcp-fs", args: ["/tmp"], env: { A: "1" } },
      { name: "bare", command: "run", args: undefined, env: undefined },
    ]);
  });
});
