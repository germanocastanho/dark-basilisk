/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, basename } from "node:path";

/**
 * Impact ratings, ordered ascending. Reverse for a most-severe-first report.
 */
export const SEVERITIES = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * One structured security finding. `id` and `createdAt` are assigned by the
 * engine; everything else comes from whoever records it.
 */
export interface Finding {
  id: string;
  severity: Severity;
  target: string;
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
  references?: string[];
  createdAt: string;
}

/** The caller-supplied part of a finding — the engine fills in id and time. */
export type FindingInput = Omit<Finding, "id" | "createdAt">;

/**
 * On-disk report: the machine-readable artifact that sits beside a
 * transcript.
 */
export interface FindingsReport {
  version: 1;
  session: string;
  createdAt: string;
  updatedAt: string;
  findings: Finding[];
}

/**
 * Append-only sink for findings during a run. Mirrors the `confirm` pattern in
 * ToolContext: a tool records through this handle and never touches the file
 * itself, keeping session-state I/O owned by the engine.
 */
export interface FindingsStore {
  /**
   * Persist a finding, assigning its id/timestamp, and return the stored
   * form.
   */
  record(input: FindingInput): Finding;
  /** Snapshot of everything recorded so far this session. */
  list(): Finding[];
  /** Path of the findings file this store writes to. */
  readonly path: string;
}

/**
 * Findings file that sits beside a session transcript
 * (`<id>.findings.json`).
 */
export function findingsPathFor(sessionPath: string): string {
  return sessionPath.endsWith(".json")
    ? `${sessionPath.slice(0, -".json".length)}.findings.json`
    : `${sessionPath}.findings.json`;
}

/**
 * Read a session's findings report, or null if none exists yet or the file is
 * unreadable. Read-only helper for the `findings` command; the live session
 * uses a FindingsStore instead.
 */
export function loadReport(sessionPath: string): FindingsReport | null {
  try {
    const doc = JSON.parse(
      readFileSync(findingsPathFor(sessionPath), "utf8"),
    ) as FindingsReport;
    return Array.isArray(doc.findings) ? doc : null;
  } catch {
    return null;
  }
}

/**
 * Open (or create) the findings store for a session. Any findings already on
 * disk are loaded so a resumed session keeps numbering and never overwrites
 * prior work. Each `record` rewrites the whole file, so a crash mid-run still
 * leaves a complete report — the same durability the transcript save gives.
 */
export function createFindingsStore(sessionPath: string): FindingsStore {
  const path = findingsPathFor(sessionPath);

  const existing = loadReport(sessionPath);
  const findings: Finding[] = existing ? existing.findings : [];
  const createdAt = existing?.createdAt ?? new Date().toISOString();

  function persist(): void {
    mkdirSync(dirname(path), { recursive: true });
    const doc: FindingsReport = {
      version: 1,
      session: basename(sessionPath),
      createdAt,
      updatedAt: new Date().toISOString(),
      findings,
    };
    writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
  }

  return {
    path,
    list: () => [...findings],
    record(input) {
      const finding: Finding = {
        id: `F-${findings.length + 1}`,
        ...input,
        createdAt: new Date().toISOString(),
      };
      findings.push(finding);
      persist();
      return finding;
    },
  };
}
