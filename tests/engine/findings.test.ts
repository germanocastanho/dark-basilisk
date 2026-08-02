/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFindingsStore,
  findingsPathFor,
  loadReport,
  type FindingInput,
} from "../../src/engine/findings.ts";

const sample: FindingInput = {
  severity: "medium",
  target: "target.example",
  title: "Issue",
  description: "Something.",
};

describe("findingsPathFor", () => {
  test("swaps a .json transcript suffix for .findings.json", () => {
    expect(findingsPathFor("/x/2026.json")).toBe("/x/2026.findings.json");
  });
  test("appends when there is no .json suffix", () => {
    expect(findingsPathFor("/x/session")).toBe("/x/session.findings.json");
  });
});

describe("createFindingsStore", () => {
  let dir: string;
  let sessionPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "basilisk-find-"));
    sessionPath = join(dir, "s.json");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test("assigns sequential ids and persists to disk", () => {
    const store = createFindingsStore(sessionPath);
    expect(store.record(sample).id).toBe("F-1");
    expect(store.record({ ...sample, title: "Second" }).id).toBe("F-2");

    const report = loadReport(sessionPath);
    expect(report).not.toBeNull();
    expect(report!.findings).toHaveLength(2);
    expect(report!.findings[0]!.createdAt).toBeTruthy();
  });

  test("a resumed store continues numbering and keeps createdAt", () => {
    const first = createFindingsStore(sessionPath);
    first.record(sample);
    const createdAt = loadReport(sessionPath)!.createdAt;

    const resumed = createFindingsStore(sessionPath);
    expect(resumed.list()).toHaveLength(1);
    expect(resumed.record({ ...sample, title: "Third" }).id).toBe("F-2");
    expect(loadReport(sessionPath)!.createdAt).toBe(createdAt);
  });

  test("loadReport returns null when nothing was recorded", () => {
    expect(loadReport(join(dir, "empty.json"))).toBeNull();
  });
});
