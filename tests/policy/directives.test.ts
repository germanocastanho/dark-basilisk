/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { expect, test } from "bun:test";
import {
  addNote,
  createDirectives,
  denyTool,
  formatDirectives,
  toolDenied,
} from "../../src/policy/directives.ts";

test("a fresh directive set is empty", () => {
  const d = createDirectives();
  expect(d.notes).toEqual([]);
  expect(d.deniedTools.size).toBe(0);
  expect(formatDirectives(d)).toBeUndefined();
});

test("addNote records a trimmed note", () => {
  const d = createDirectives();
  addNote(d, "  never touch prod  ");
  expect(d.notes).toEqual(["never touch prod"]);
});

test("addNote ignores blank text", () => {
  const d = createDirectives();
  addNote(d, "   ");
  expect(d.notes).toEqual([]);
});

test("denyTool marks a tool as denied", () => {
  const d = createDirectives();
  denyTool(d, "tcp_scan");
  expect(toolDenied(d, "tcp_scan")).toBe(true);
  expect(toolDenied(d, "dns_lookup")).toBe(false);
});

test("toolDenied is false with no directives", () => {
  expect(toolDenied(undefined, "tcp_scan")).toBe(false);
});

test("formatDirectives renders notes and denied tools", () => {
  const d = createDirectives();
  addNote(d, "only passive recon");
  denyTool(d, "tcp_scan");
  const rendered = formatDirectives(d);
  expect(rendered).toContain("only passive recon");
  expect(rendered).toContain("Do not call: tcp_scan");
});
