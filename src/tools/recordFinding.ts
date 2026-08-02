/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import type { Tool } from "./types.ts";
import {
  SEVERITIES,
  type FindingInput,
  type Severity,
} from "../engine/findings.ts";

function isSeverity(value: unknown): value is Severity {
  return (
    typeof value === "string" &&
    (SEVERITIES as readonly string[]).includes(value)
  );
}

function cleanString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

/**
 * Record a structured finding to the session's findings log. Not risky — it
 * writes a local report beside the transcript and never touches the target — so
 * it runs without a gate. The model calls it once per confirmed observation.
 */
export const recordFinding: Tool = {
  name: "record_finding",
  description:
    "Record a structured security finding to the session's findings log (a machine-readable report saved beside the transcript). Call it when you confirm something worth reporting: a vulnerability, misconfiguration, or notable exposure.",
  schema: {
    type: "object",
    properties: {
      severity: {
        type: "string",
        enum: [...SEVERITIES],
        description: "Impact rating.",
      },
      target: {
        type: "string",
        description: "Affected asset — host, URL, or host:port.",
      },
      title: {
        type: "string",
        description: "Short one-line summary of the finding.",
      },
      description: {
        type: "string",
        description: "What it is and why it matters.",
      },
      evidence: {
        type: "string",
        description: "The observation supporting the finding.",
      },
      recommendation: {
        type: "string",
        description: "How to remediate it.",
      },
      references: {
        type: "array",
        items: { type: "string" },
        description: "CVE/CWE ids or URLs.",
      },
    },
    required: ["severity", "target", "title", "description"],
    additionalProperties: false,
  },

  async run(input, ctx) {
    const { severity, references } = input;
    if (!isSeverity(severity)) {
      return {
        content: `Invalid severity. Use one of: ${SEVERITIES.join(", ")}`,
        isError: true,
      };
    }

    const target = cleanString(input.target);
    const title = cleanString(input.title);
    const description = cleanString(input.description);
    if (!target) return { content: "Missing target.", isError: true };
    if (!title) return { content: "Missing title.", isError: true };
    if (!description) return { content: "Missing description.", isError: true };

    const evidence = cleanString(input.evidence);
    const recommendation = cleanString(input.recommendation);
    const refs = Array.isArray(references)
      ? references.filter(
          (r): r is string => typeof r === "string" && r.trim() !== "",
        )
      : [];

    const finding: FindingInput = {
      severity,
      target,
      title,
      description,
      ...(evidence ? { evidence } : {}),
      ...(recommendation ? { recommendation } : {}),
      ...(refs.length > 0 ? { references: refs } : {}),
    };

    const saved = ctx.findings.record(finding);
    const total = ctx.findings.list().length;
    return {
      content: `Recorded ${saved.id} [${saved.severity}] ${saved.title} — ${total} finding(s) logged at ${ctx.findings.path}`,
    };
  },
};
