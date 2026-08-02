/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { expect, test, describe } from "bun:test";
import { retryAfterMs, formatDuration } from "../../src/engine/conversation.ts";

describe("retryAfterMs", () => {
  test("prefers retry-after-ms (in milliseconds)", () => {
    expect(retryAfterMs(new Headers({ "retry-after-ms": "1500" }))).toBe(1500);
  });

  test("retry-after-ms wins over retry-after", () => {
    const h = new Headers({ "retry-after-ms": "1500", "retry-after": "30" });
    expect(retryAfterMs(h)).toBe(1500);
  });

  test("retry-after in delta-seconds becomes milliseconds", () => {
    expect(retryAfterMs(new Headers({ "retry-after": "30" }))).toBe(30_000);
  });

  test("falls through invalid retry-after-ms to retry-after", () => {
    const h = new Headers({ "retry-after-ms": "nope", "retry-after": "5" });
    expect(retryAfterMs(h)).toBe(5000);
  });

  test("zero or negative delta-seconds yield null", () => {
    expect(retryAfterMs(new Headers({ "retry-after": "0" }))).toBeNull();
    expect(retryAfterMs(new Headers({ "retry-after": "-5" }))).toBeNull();
  });

  test("HTTP-date in the future yields a positive delta", () => {
    const future = new Date(Date.now() + 60_000).toUTCString();
    const ms = retryAfterMs(new Headers({ "retry-after": future }));
    expect(ms).not.toBeNull();
    expect(ms!).toBeGreaterThan(55_000);
    expect(ms!).toBeLessThanOrEqual(61_000);
  });

  test("HTTP-date in the past yields null", () => {
    const past = new Date(Date.now() - 60_000).toUTCString();
    expect(retryAfterMs(new Headers({ "retry-after": past }))).toBeNull();
  });

  test("no relevant headers yields null", () => {
    expect(retryAfterMs(new Headers())).toBeNull();
  });
});

describe("formatDuration", () => {
  test("sub-minute", () => {
    expect(formatDuration(8000)).toBe("8s");
    expect(formatDuration(500)).toBe("1s"); // clamped to at least 1s
  });

  test("minutes with and without seconds", () => {
    expect(formatDuration(120_000)).toBe("2m");
    expect(formatDuration(150_000)).toBe("2m 30s");
  });

  test("hours with and without minutes", () => {
    expect(formatDuration(3_600_000)).toBe("1h");
    expect(formatDuration(3_900_000)).toBe("1h 5m");
  });
});
