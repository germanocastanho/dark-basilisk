#!/usr/bin/env bun
/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { writeFileSync } from "node:fs";
import { Command } from "commander";
import type Anthropic from "@anthropic-ai/sdk";
import { createClient } from "./engine/model.ts";
import { runTurn, type TurnEvent } from "./engine/conversation.ts";
import {
  newSessionPath,
  loadSession,
  saveSession,
  listSessions,
} from "./engine/history.ts";
import { loadConfig, configPath } from "./engine/config.ts";
import { loadExtensions } from "./engine/extensions.ts";
import {
  bundledSkillsDir,
  discoverSkills,
  skillsDir,
} from "./engine/skills.ts";
import {
  createFindingsStore,
  findingsPathFor,
  loadReport,
  SEVERITIES,
  type Finding,
  type FindingsReport,
  type Severity,
} from "./engine/findings.ts";
import {
  renderMarkdown,
  renderPdf,
  type ReportFormat,
} from "./engine/report.ts";
import { denyAll } from "./policy/approval.ts";
import { createSkillGate } from "./policy/skillGate.ts";
import {
  createDirectives,
  addNote,
  denyTool,
  formatDirectives,
  type OperatorDirectives,
} from "./policy/directives.ts";
import type { ToolContext } from "./tools/types.ts";
import { colors, write } from "./ui/stream.ts";
import { printBanner } from "./ui/banner.ts";
import { startChat } from "./ui/chat.tsx";

interface ChatOptions {
  resume?: string;
  directives: OperatorDirectives;
}

/** One line summarizing startup directives, if any were given. */
function directivesNote(directives: OperatorDirectives): string[] {
  if (directives.notes.length === 0 && directives.deniedTools.size === 0) {
    return [];
  }
  return [
    `Operator directives: ${directives.notes.length} note(s), ` +
      `${directives.deniedTools.size} denied tool(s). See /directives.`,
  ];
}

/**
 * Start an interactive session. Resolves auth and settings up front (so a clean
 * error prints normally), then hands the conversation to the Ink app, which owns
 * the terminal: input, streaming, the approval gate, and per-turn persistence.
 */
async function chat(options: ChatOptions): Promise<void> {
  const client = createClient();
  const config = loadConfig();
  const extensions = await loadExtensions(config);

  const sessionPath = options.resume ?? newSessionPath();
  const history = options.resume ? loadSession(options.resume) : [];

  const banner = [
    `Model: ${config.model.model}`,
    options.resume
      ? `Resumed ${history.length} messages from ${sessionPath}.`
      : `Session: ${sessionPath}`,
    ...extensions.notes,
    ...directivesNote(options.directives),
    "Authorized testing only. /help for commands, /exit to quit.",
  ];

  try {
    await startChat({
      client,
      history,
      sessionPath,
      model: config.model,
      config,
      banner,
      briefing: extensions.briefing,
      directives: options.directives,
    });
  } finally {
    await extensions.close();
  }
  // Safety-net save; the app already persists after every turn.
  saveSession(sessionPath, history);
}

/** Render a turn event to stdout — the non-interactive counterpart to the Ink UI. */
function printTurnEvent(event: TurnEvent): void {
  switch (event.type) {
    case "thinking_start":
      write(colors.dim("\nthinking… "));
      break;
    case "thinking":
      write(colors.dim(event.text));
      break;
    case "text":
      write(event.text);
      break;
    case "tool":
      write(colors.accent(`\n→ ${event.name}\n`));
      break;
    case "notice":
      write(
        (event.level === "error" ? colors.error : colors.warn)(
          `\n${event.text}\n`,
        ),
      );
      break;
  }
}

/**
 * Run a single task unattended: no prompts, risky tools auto-denied (`denyAll`).
 * Read-only recon still runs, findings are recorded, and the transcript is saved
 * so `basilisk findings`/`report` work afterwards.
 */
async function runOnce(
  task: string,
  directives: OperatorDirectives,
): Promise<void> {
  const client = createClient();
  const config = loadConfig();
  const extensions = await loadExtensions(config);
  const sessionPath = newSessionPath();

  const ctx: ToolContext = {
    workdir: process.cwd(),
    confirm: denyAll,
    config,
    findings: createFindingsStore(sessionPath),
    skillGate: createSkillGate(),
    directives,
  };

  write(printBanner());
  write(
    colors.dim(
      `basilisk (headless) · ${config.model.model} · ${sessionPath}\n`,
    ),
  );
  for (const note of extensions.notes) write(colors.dim(`${note}\n`));
  for (const note of directivesNote(directives)) {
    write(colors.dim(`${note}\n`));
  }
  write(colors.dim("Risky tools are auto-denied in this mode.\n\n"));

  const history: Anthropic.MessageParam[] = [{ role: "user", content: task }];
  try {
    await runTurn(
      client,
      history,
      ctx,
      printTurnEvent,
      config.model,
      extensions.briefing,
      formatDirectives(directives),
    );
  } catch (err) {
    write(
      colors.error(`\n${err instanceof Error ? err.message : String(err)}\n`),
    );
    process.exitCode = 1;
  } finally {
    await extensions.close();
    saveSession(sessionPath, history);
  }

  const count = ctx.findings.list().length;
  write(
    colors.dim(
      `\n\nFindings recorded: ${count}. ` +
        `Report with: basilisk report --session ${sessionPath}\n`,
    ),
  );
}

/** Print saved sessions so the operator can pick one to resume. */
function printSessions(): void {
  const sessions = listSessions();
  if (sessions.length === 0) {
    write("No saved sessions.\n");
    return;
  }
  write(colors.bold("Saved sessions (newest first):\n"));
  for (const s of sessions) {
    write(`  ${s.updatedAt}  ${s.turns} msgs  ${s.path}\n`);
  }
  write(colors.dim("\nResume with: basilisk --resume <path>\n"));
}

/** Paint a severity label in a color that matches its weight. */
function colorSeverity(severity: Severity, text: string): string {
  if (severity === "critical" || severity === "high") return colors.error(text);
  if (severity === "medium") return colors.warn(text);
  if (severity === "low") return colors.accent(text);
  return colors.dim(text);
}

interface FindingsOptions {
  session?: string;
  json?: boolean;
}

/** Print a session's findings — a human report, or the raw JSON with --json. */
function printFindings(options: FindingsOptions): void {
  let sessionPath = options.session;
  if (!sessionPath) {
    const recent = listSessions();
    if (recent.length === 0) {
      write("No saved sessions.\n");
      return;
    }
    sessionPath = recent[0]!.path;
  }

  const report = loadReport(sessionPath);

  if (options.json) {
    write(
      `${JSON.stringify(
        report ?? { version: 1, session: sessionPath, findings: [] },
        null,
        2,
      )}\n`,
    );
    return;
  }

  const findings = report?.findings ?? [];
  if (findings.length === 0) {
    write(`No findings recorded for ${sessionPath}.\n`);
    return;
  }

  write(
    colors.bold(`Findings for ${sessionPath} — ${findings.length} total\n\n`),
  );
  const grouped = new Map<Severity, Finding[]>();
  for (const f of findings) {
    const group = grouped.get(f.severity) ?? [];
    group.push(f);
    grouped.set(f.severity, group);
  }
  // Most severe first.
  for (const severity of [...SEVERITIES].reverse()) {
    const group = grouped.get(severity);
    if (!group || group.length === 0) continue;
    write(
      colorSeverity(severity, `${severity.toUpperCase()} (${group.length})\n`),
    );
    for (const f of group) {
      write(`  ${f.id}  ${f.title}\n`);
      write(colors.dim(`        target: ${f.target}\n`));
      write(colors.dim(`        ${f.description}\n`));
      if (f.evidence) write(colors.dim(`        evidence: ${f.evidence}\n`));
      if (f.recommendation)
        write(colors.dim(`        fix: ${f.recommendation}\n`));
      if (f.references?.length) {
        write(colors.dim(`        refs: ${f.references.join(", ")}\n`));
      }
    }
    write("\n");
  }
  write(colors.dim(`Raw report: ${findingsPathFor(sessionPath)}\n`));
}

interface ReportOptions {
  session?: string;
  format?: string;
  out?: string;
}

/**
 * Render a session's findings as a deliverable report (Markdown or PDF). Markdown
 * goes to stdout or a file; PDF is binary and requires `--out`. Builds on the
 * same findings store the session writes.
 */
async function printReport(options: ReportOptions): Promise<void> {
  if (options.format && options.format !== "md" && options.format !== "pdf") {
    write(colors.error(`Unknown format "${options.format}". Use md or pdf.\n`));
    process.exitCode = 1;
    return;
  }
  const format: ReportFormat = options.format === "pdf" ? "pdf" : "md";

  let sessionPath = options.session;
  if (!sessionPath) {
    const recent = listSessions();
    if (recent.length === 0) {
      write("No saved sessions.\n");
      return;
    }
    sessionPath = recent[0]!.path;
  }

  const now = new Date().toISOString();
  const report: FindingsReport = loadReport(sessionPath) ?? {
    version: 1,
    session: sessionPath,
    createdAt: now,
    updatedAt: now,
    findings: [],
  };

  if (format === "pdf") {
    if (!options.out) {
      write(colors.error("PDF output is binary — pass --out <file>.\n"));
      process.exitCode = 1;
      return;
    }
    writeFileSync(options.out, await renderPdf(report, now));
    write(
      colors.dim(
        `Wrote pdf report (${report.findings.length} findings) to ${options.out}\n`,
      ),
    );
    return;
  }

  const md = renderMarkdown(report, now);
  if (options.out) {
    writeFileSync(options.out, md, "utf8");
    write(
      colors.dim(
        `Wrote md report (${report.findings.length} findings) to ${options.out}\n`,
      ),
    );
    return;
  }
  write(md.endsWith("\n") ? md : `${md}\n`);
}

/** Commander repeatable-option accumulator. */
function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

const program = new Command();

program
  .name("basilisk")
  .description(
    "Command-line cybersecurity agent for authorized security testing",
  )
  .version("0.1.0")
  .option("--resume <path>", "Resume a saved session file")
  .option(
    "-p, --print <task>",
    "Run a single task headless (no prompts, risky tools auto-denied)",
  )
  .option(
    "--instruct <text>",
    "Operator directive for this session (repeatable)",
    collect,
    [] as string[],
  )
  .option(
    "--deny-tool <name>",
    "Forbid a tool for this session (repeatable)",
    collect,
    [] as string[],
  )
  .action(
    async (opts: {
      resume?: string;
      print?: string;
      instruct: string[];
      denyTool: string[];
    }) => {
      const directives = createDirectives();
      for (const note of opts.instruct) addNote(directives, note);
      for (const name of opts.denyTool) denyTool(directives, name);
      try {
        if (opts.print !== undefined) {
          await runOnce(opts.print, directives);
        } else {
          await chat({ resume: opts.resume, directives });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        write(colors.error(`\nfatal: ${message}\n`));
        process.exitCode = 1;
      }
    },
  );

program
  .command("sessions")
  .description("List saved sessions")
  .action(() => {
    printSessions();
  });

program
  .command("findings")
  .description("Print the findings report for a session")
  .option("--session <path>", "Session file (defaults to the most recent)")
  .option("--json", "Print the raw findings JSON instead of a report")
  .action((opts: FindingsOptions) => {
    printFindings(opts);
  });

program
  .command("report")
  .description("Render a session's findings as a Markdown or PDF report")
  .option("--session <path>", "Session file (defaults to the most recent)")
  .option("--format <format>", "Output format: md or pdf", "md")
  .option("--out <file>", "Write to a file (required for pdf)")
  .action(async (opts: ReportOptions) => {
    await printReport(opts);
  });

program
  .command("skills")
  .description("List installed skill playbooks and the skills directory")
  .action(() => {
    const skills = discoverSkills();
    if (skills.length === 0) {
      write(`No skills installed. Add them under:\n  ${skillsDir()}\n`);
      write(
        colors.dim(
          "Each skill is a <name>/SKILL.md with name + description " +
            "frontmatter.\n",
        ),
      );
      return;
    }
    write(colors.bold(`Installed skills (${skills.length}):\n`));
    for (const s of skills) {
      write(`  ${s.name}\n`);
      write(colors.dim(`      ${s.description}\n`));
    }
    write(colors.dim(`\nBundled: ${bundledSkillsDir()}\n`));
    write(colors.dim(`User:    ${skillsDir()}\n`));
  });

program
  .command("config")
  .description("Print the active configuration and its file path")
  .action(() => {
    write(colors.bold("Active configuration:\n"));
    write(`${JSON.stringify(loadConfig(), null, 2)}\n`);
    write(colors.dim(`\nLoaded from: ${configPath()}\n`));
    write(
      colors.dim("Missing or invalid keys fall back to built-in defaults.\n"),
    );
  });

program.parseAsync(process.argv);
