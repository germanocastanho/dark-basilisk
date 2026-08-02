/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { useReducer, useRef, useState } from "react";
import { Box, Static, Text, useApp, useInput, useStdout } from "ink";
import TextInput from "ink-text-input";
import Spinner from "ink-spinner";
import Anthropic from "@anthropic-ai/sdk";
import { runTurn, type TurnEvent } from "../engine/conversation.ts";
import { saveSession } from "../engine/history.ts";
import { createFindingsStore } from "../engine/findings.ts";
import { createSkillGate } from "../policy/skillGate.ts";
import type { Config } from "../engine/config.ts";
import type { ModelConfig } from "../engine/model.ts";
import { listTools } from "../tools/registry.ts";
import { discoverSkills } from "../engine/skills.ts";
import type { ToolContext } from "../tools/types.ts";
import { BANNER_LINES, BANNER_TAGLINE } from "./banner.ts";
import { Markdown } from "./markdown.tsx";

/** A committed line in the scrollback log. */
type Entry =
  | { id: number; kind: "user"; text: string }
  | { id: number; kind: "agent"; text: string }
  | { id: number; kind: "banner"; text: string }
  | { id: number; kind: "tool"; name: string }
  | { id: number; kind: "notice"; level: "warn" | "error"; text: string }
  | { id: number; kind: "system"; text: string };

/** In-progress assistant output for the current turn, rendered below the log. */
interface Live {
  text: string;
}

/**
 * Split streamed output into the part safe to commit and the part still growing.
 * A block is "settled" once a blank line follows it while no code fence is open,
 * so everything up to the last such boundary will never change again. Committing
 * it into `<Static>` keeps the live (repainted) frame small — the fix that stops
 * tall-frame repaints from flickering and yanking the scroll position around.
 * See [[ui-conventions]].
 */
function splitSettled(buffer: string): [settled: string, rest: string] {
  const lines = buffer.split("\n");
  let fenceOpen = false;
  let lastBoundary = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*```/.test(lines[i]!)) fenceOpen = !fenceOpen;
    else if (!fenceOpen && lines[i]!.trim() === "") lastBoundary = i;
  }
  if (lastBoundary < 0) return ["", buffer];
  return [
    lines.slice(0, lastBoundary + 1).join("\n"),
    lines.slice(lastBoundary + 1).join("\n"),
  ];
}

interface Approval {
  description: string;
  resolve(ok: boolean): void;
}

export interface AppProps {
  client: Anthropic;
  /** Full conversation, mutated in place across turns. */
  history: Anthropic.MessageParam[];
  sessionPath: string;
  model: ModelConfig;
  config: Config;
  /** Startup lines to seed the log with. */
  banner: string[];
  /** Session briefing (skills + MCP) appended after the system prompt. */
  briefing?: string;
}

/** Turn an SDK/network error into a short, actionable line for the operator. */
function describeTurnError(err: unknown): string {
  if (err instanceof Anthropic.RateLimitError) {
    return "Rate limited by the API — usage limit hit. Wait a bit and try again.";
  }
  if (err instanceof Anthropic.AuthenticationError) {
    return "Authentication failed. Check that ANTHROPIC_API_KEY is set and valid.";
  }
  if (err instanceof Anthropic.APIError) {
    return `API error ${err.status ?? "?"}: ${err.message}`;
  }
  return err instanceof Error ? err.message : String(err);
}

const HELP_LINES = [
  "In-session commands:",
  "  /help          show this help",
  "  /tools         list the agent's tools and which are gated",
  "  /skills        list installed skill playbooks",
  "  /exit, /quit   end the session",
  "",
  "Anything else is sent to the agent as a request.",
];

/** Render one committed log entry. */
function EntryView({ entry }: { entry: Entry }): React.ReactNode {
  switch (entry.kind) {
    case "user":
      return (
        <Text>
          <Text color="cyan">prompt › </Text>
          {entry.text}
        </Text>
      );
    case "agent":
      return <Markdown text={entry.text} />;
    case "banner":
      return <Text color="green">{entry.text}</Text>;
    case "tool":
      return <Text color="cyan">→ {entry.name}</Text>;
    case "notice":
      return (
        <Text color={entry.level === "error" ? "red" : "yellow"}>
          {entry.text}
        </Text>
      );
    case "system":
      return <Text dimColor>{entry.text}</Text>;
  }
}

/** Modal approval gate. Captures a single y/n while a risky tool waits. */
function ApprovalPrompt({
  description,
  onAnswer,
}: {
  description: string;
  onAnswer(ok: boolean): void;
}): React.ReactNode {
  useInput((input, key) => {
    if (input === "y" || input === "Y") onAnswer(true);
    else if (input === "n" || input === "N" || key.return || key.escape) {
      onAnswer(false);
    }
  });
  return (
    <Box flexDirection="column" marginY={1}>
      <Text color="yellow">! {description}</Text>
      <Text>
        Proceed? <Text dimColor>[y/N]</Text>
      </Text>
    </Box>
  );
}

export function App({
  client,
  history,
  sessionPath,
  model,
  config,
  banner,
  briefing,
}: AppProps): React.ReactNode {
  const { exit } = useApp();
  const { stdout } = useStdout();

  // Reserve the last terminal column for every repainted (non-<Static>) line.
  // Ink's log-update erases `output.split("\n").length` rows — a logical-line
  // count that ignores terminal soft-wrap. If any repainted line reaches the
  // full width, the terminal wraps it into two physical rows while Ink erases
  // only one, leaving the stray row on screen: the "mirror" the operator saw
  // while typing past the edge. Wrapping the live regions to `columns - 1` keeps
  // Ink's line count equal to the physical rows, so nothing is left behind.
  const columns = stdout?.columns ?? 80;
  const liveWidth = Math.max(20, columns - 1);

  const idRef = useRef(0);
  const nextId = () => idRef.current++;

  // Seed the log with the banner as its first committed lines. Because these
  // live inside <Static>, Ink prints them once and lets them scroll up with the
  // conversation instead of repainting them every frame.
  const [entries, setEntries] = useState<Entry[]>(() => [
    ...BANNER_LINES.map(
      (text) => ({ id: nextId(), kind: "banner", text }) as Entry,
    ),
    { id: nextId(), kind: "system", text: BANNER_TAGLINE } as Entry,
    { id: nextId(), kind: "system", text: "" } as Entry,
    ...banner.map((text) => ({ id: nextId(), kind: "system", text }) as Entry),
  ]);
  const [input, setInput] = useState("");
  const [running, setRunning] = useState(false);
  const [approval, setApproval] = useState<Approval | null>(null);

  const liveRef = useRef<Live>({ text: "" });
  const [, forceRender] = useReducer((n: number) => n + 1, 0);

  // Built once so the findings store and confirm bridge persist across turns.
  const ctxRef = useRef<ToolContext | null>(null);
  if (ctxRef.current === null) {
    ctxRef.current = {
      workdir: process.cwd(),
      confirm: (description) =>
        new Promise<boolean>((resolve) =>
          setApproval({ description, resolve }),
        ),
      config,
      findings: createFindingsStore(sessionPath),
      skillGate: createSkillGate(),
    };
  }

  /** Flush the streaming buffer into committed entries and clear it. */
  function drainLive(): Entry[] {
    const { text } = liveRef.current;
    const out: Entry[] = [];
    if (text.trim()) out.push({ id: nextId(), kind: "agent", text });
    liveRef.current = { text: "" };
    return out;
  }

  function pushEntries(...items: Entry[]): void {
    setEntries((prev) => [...prev, ...items]);
  }

  function emit(event: TurnEvent): void {
    switch (event.type) {
      case "thinking_start":
      case "thinking":
        // Reasoning is intentionally not surfaced in the UI.
        break;
      case "text": {
        liveRef.current.text += event.text;
        // Commit any settled block(s) to <Static> so the live frame stays a few
        // lines tall at most — a tall repainted frame is what flickered before.
        const [settled, rest] = splitSettled(liveRef.current.text);
        if (settled) {
          liveRef.current.text = rest;
          if (settled.trim()) {
            pushEntries({ id: nextId(), kind: "agent", text: settled });
          }
        }
        forceRender();
        break;
      }
      case "tool":
        pushEntries(...drainLive(), {
          id: nextId(),
          kind: "tool",
          name: event.name,
        });
        break;
      case "notice":
        pushEntries(...drainLive(), {
          id: nextId(),
          kind: "notice",
          level: event.level,
          text: event.text,
        });
        break;
    }
  }

  function handleSlash(line: string): boolean {
    if (line === "/exit" || line === "/quit") {
      exit();
      return true;
    }
    if (line === "/help") {
      pushEntries(
        ...HELP_LINES.map(
          (text) => ({ id: nextId(), kind: "system", text }) as Entry,
        ),
      );
      return true;
    }
    if (line === "/tools") {
      const lines = listTools().map((tool) => {
        const gate = tool.risky ? "gated" : "open ";
        return `  ${gate}  ${tool.name.padEnd(18)} ${tool.description}`;
      });
      pushEntries(
        { id: nextId(), kind: "system", text: "Tools:" },
        ...lines.map(
          (text) => ({ id: nextId(), kind: "system", text }) as Entry,
        ),
        {
          id: nextId(),
          kind: "system",
          text: "gated = requires your approval per call.",
        },
      );
      return true;
    }
    if (line === "/skills") {
      const skills = discoverSkills();
      if (skills.length === 0) {
        pushEntries({
          id: nextId(),
          kind: "system",
          text: "No skills installed. Add them under the skills data dir.",
        });
        return true;
      }
      pushEntries(
        { id: nextId(), kind: "system", text: "Installed skills:" },
        ...skills.map(
          (s) =>
            ({
              id: nextId(),
              kind: "system",
              text: `  ${s.name.padEnd(18)} ${s.description}`,
            }) as Entry,
        ),
        {
          id: nextId(),
          kind: "system",
          text: "The agent reads one in full with load_skill.",
        },
      );
      return true;
    }
    return false;
  }

  async function submit(value: string): Promise<void> {
    const line = value.trim();
    setInput("");
    if (line.length === 0 || running) return;
    if (handleSlash(line)) return;

    pushEntries({ id: nextId(), kind: "user", text: line });

    // Roll back to this mark if the turn fails, so a rate limit or network blip
    // doesn't kill the session or leave a dangling half-turn.
    const mark = history.length;
    history.push({ role: "user", content: line });
    setRunning(true);
    try {
      await runTurn(client, history, ctxRef.current!, emit, model, briefing);
      pushEntries(...drainLive());
      saveSession(sessionPath, history);
    } catch (err) {
      history.length = mark;
      pushEntries(...drainLive(), {
        id: nextId(),
        kind: "notice",
        level: "error",
        text: describeTurnError(err),
      });
    } finally {
      setRunning(false);
    }
  }

  const live = liveRef.current;

  return (
    <Box flexDirection="column">
      <Static items={entries}>
        {(entry) => <EntryView key={entry.id} entry={entry} />}
      </Static>

      {live.text.length > 0 && (
        <Box width={liveWidth}>
          <Text>{live.text}</Text>
        </Box>
      )}

      {approval !== null ? (
        <ApprovalPrompt
          description={approval.description}
          onAnswer={(ok) => {
            approval.resolve(ok);
            setApproval(null);
          }}
        />
      ) : running ? (
        <Box>
          <Text color="cyan">
            <Spinner type="dots" />
          </Text>
          <Text dimColor> working…</Text>
        </Box>
      ) : (
        <Box width={liveWidth}>
          {/* Non-shrinking prefix + input in a flex-grow box: keeps "prompt › "
              intact (a plain sibling Text would be shrunk by Yoga) and lets Ink
              wrap the typed value inside the reserved width instead of letting
              the terminal soft-wrap it. */}
          <Box flexShrink={0}>
            <Text color="cyan">prompt › </Text>
          </Box>
          <Box flexGrow={1}>
            <TextInput value={input} onChange={setInput} onSubmit={submit} />
          </Box>
        </Box>
      )}
    </Box>
  );
}
