/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { resolveAuth } from "../../src/engine/auth.ts";

describe("resolveAuth", () => {
  const prevApiKey = process.env.ANTHROPIC_API_KEY;

  beforeEach(() => {
    delete process.env.ANTHROPIC_API_KEY;
  });

  afterEach(() => {
    if (prevApiKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prevApiKey;
  });

  test("reads the API key from the environment", () => {
    process.env.ANTHROPIC_API_KEY = "sk-test-123";
    const auth = resolveAuth();
    expect(auth.apiKey).toBe("sk-test-123");
    expect(auth.source).toBe("ANTHROPIC_API_KEY");
  });

  test("trims surrounding whitespace", () => {
    process.env.ANTHROPIC_API_KEY = "  sk-test-123  ";
    expect(resolveAuth().apiKey).toBe("sk-test-123");
  });

  test("throws when the key is missing", () => {
    expect(() => resolveAuth()).toThrow(/ANTHROPIC_API_KEY/);
  });

  test("throws when the key is blank", () => {
    process.env.ANTHROPIC_API_KEY = "   ";
    expect(() => resolveAuth()).toThrow(/ANTHROPIC_API_KEY/);
  });
});
