/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Shared HTTP helpers for the active web-probe tools. Every probe reaches the
 * target under test, so they all bound the request with a timeout and cap the
 * body they read — keeping a probe from becoming a flooding or memory hazard.
 */

const DEFAULT_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 128 * 1024;

/** Result of a single bounded request. `error` is set instead of throwing. */
export interface ProbeResponse {
  status: number;
  statusText: string;
  headers: Headers;
  body: string;
  location: string | null;
  elapsedMs: number;
  error?: string;
}

export interface ProbeOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  redirect?: RequestRedirect;
}

/** Validate and parse an absolute http(s) URL, or return null. */
export function parseHttpUrl(value: unknown): URL | null {
  if (typeof value !== "string") return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  return url.protocol === "http:" || url.protocol === "https:" ? url : null;
}

/**
 * Perform one bounded HTTP request. Never throws: a network error, timeout, or
 * abort comes back as a `ProbeResponse` with `error` set and `status` 0, so
 * callers can diff outcomes uniformly.
 */
export async function probeRequest(
  target: URL | string,
  options: ProbeOptions = {},
): Promise<ProbeResponse> {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(target, {
      method: options.method ?? "GET",
      headers: options.headers,
      body: options.body,
      redirect: options.redirect ?? "manual",
      signal: controller.signal,
    });
    const raw = await res.text();
    const body =
      raw.length > MAX_BODY_BYTES ? raw.slice(0, MAX_BODY_BYTES) : raw;
    return {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
      body,
      location: res.headers.get("location"),
      elapsedMs: Date.now() - started,
    };
  } catch (err) {
    return {
      status: 0,
      statusText: "",
      headers: new Headers(),
      body: "",
      location: null,
      elapsedMs: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run an async mapper over items with a bounded worker pool, so a probe fans
 * out without flooding the target. Preserves input order in the output.
 */
export async function boundedPool<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  async function run(): Promise<void> {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await worker(items[index]!, index);
    }
  }
  const size = Math.min(Math.max(1, concurrency), items.length || 1);
  await Promise.all(Array.from({ length: size }, run));
  return results;
}
