/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWordlist } from "../../src/tools/wordlists.ts";

const dir = mkdtempSync(join(tmpdir(), "basilisk-wl-"));

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("loadWordlist", () => {
  test("strips comments and blanks, dedupes, keeps order", () => {
    const file = join(dir, "list.txt");
    writeFileSync(
      file,
      ["# header", "", "admin", "  login  ", "admin", "# c", "api", ""].join(
        "\n",
      ),
    );
    expect(loadWordlist(file, 100)).toEqual(["admin", "login", "api"]);
  });

  test("enforces the cap", () => {
    const file = join(dir, "capped.txt");
    writeFileSync(file, ["a", "b", "c", "d", "e"].join("\n"));
    expect(loadWordlist(file, 3)).toEqual(["a", "b", "c"]);
  });

  test("loads an absolute path directly", () => {
    const file = join(dir, "abs.txt");
    writeFileSync(file, "solo\n");
    expect(loadWordlist(file, 10)).toEqual(["solo"]);
  });

  test("throws on an unreadable path", () => {
    const missing = join(dir, "nope", "missing.txt");
    expect(() => loadWordlist(missing, 10)).toThrow();
  });
});
