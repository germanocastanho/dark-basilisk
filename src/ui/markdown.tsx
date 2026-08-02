/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { Box, Text } from "ink";

/**
 * A dependency-free Markdown renderer for the terminal. It covers the subset the
 * agent actually emits — headings, bullet/numbered lists, blockquotes, fenced
 * code, horizontal rules, and inline bold/italic/code/strikethrough/links — and
 * maps each onto Ink `<Text>` styling. Anything it doesn't recognize falls
 * through as plain text, so partial or unusual output never breaks the frame.
 *
 * Rendering is intentionally line-oriented (one `<Text>` per source line) so it
 * composes cleanly inside `<Static>`: Ink prints each committed block once and
 * never has to reflow it. See [[ui-conventions]].
 */

/** Emphasis/link markers, tried longest-first so `***` beats `**` beats `*`. */
const INLINE_PATTERNS: {
  re: RegExp;
  render(inner: React.ReactNode[], key: string, url?: string): React.ReactNode;
}[] = [
  {
    re: /\*\*\*([^*]+)\*\*\*/,
    render: (inner, key) => (
      <Text key={key} bold italic>
        {inner}
      </Text>
    ),
  },
  {
    re: /___([^_]+)___/,
    render: (inner, key) => (
      <Text key={key} bold italic>
        {inner}
      </Text>
    ),
  },
  {
    re: /\*\*([^*]+)\*\*/,
    render: (inner, key) => (
      <Text key={key} bold>
        {inner}
      </Text>
    ),
  },
  {
    re: /__([^_]+)__/,
    render: (inner, key) => (
      <Text key={key} bold>
        {inner}
      </Text>
    ),
  },
  {
    re: /(?<![A-Za-z0-9])\*([^*]+)\*(?![A-Za-z0-9])/,
    render: (inner, key) => (
      <Text key={key} italic>
        {inner}
      </Text>
    ),
  },
  {
    re: /(?<![A-Za-z0-9])_([^_]+)_(?![A-Za-z0-9])/,
    render: (inner, key) => (
      <Text key={key} italic>
        {inner}
      </Text>
    ),
  },
  {
    re: /~~([^~]+)~~/,
    render: (inner, key) => (
      <Text key={key} strikethrough>
        {inner}
      </Text>
    ),
  },
  {
    re: /\[([^\]]+)\]\(([^)]+)\)/,
    render: (inner, key, url) => (
      <Text key={key}>
        <Text underline color="cyan">
          {inner}
        </Text>
        <Text dimColor> ({url})</Text>
      </Text>
    ),
  },
];

/** Apply emphasis/link markup recursively, returning styled Ink nodes. */
function parseEmphasis(text: string, keyBase: string): React.ReactNode[] {
  // Find the earliest-starting marker; ties break on pattern order (priority).
  let best: { index: number; match: RegExpMatchArray; pat: number } | null =
    null;
  for (let p = 0; p < INLINE_PATTERNS.length; p++) {
    const m = INLINE_PATTERNS[p]!.re.exec(text);
    if (m && (best === null || m.index < best.index)) {
      best = { index: m.index, match: m, pat: p };
    }
  }
  if (best === null) return text ? [text] : [];

  const { index, match, pat } = best;
  const before = text.slice(0, index);
  const after = text.slice(index + match[0].length);
  const isLink = INLINE_PATTERNS[pat]!.re.source.startsWith("\\[");
  const innerText = match[1] ?? "";
  const url = isLink ? match[2] : undefined;

  const node = INLINE_PATTERNS[pat]!.render(
    // Links carry a URL, not nestable emphasis; everything else recurses.
    isLink ? [innerText] : parseEmphasis(innerText, `${keyBase}i`),
    `${keyBase}m`,
    url,
  );

  return [
    ...(before ? [before] : []),
    node,
    ...parseEmphasis(after, `${keyBase}a`),
  ];
}

/** Render one line's inline content: code spans first, then emphasis. */
function renderInline(text: string, keyBase: string): React.ReactNode[] {
  const parts = text.split(/(`[^`]+`)/g);
  const nodes: React.ReactNode[] = [];
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      nodes.push(
        <Text key={`${keyBase}c${i}`} color="cyan">
          {part.slice(1, -1)}
        </Text>,
      );
    } else if (part) {
      nodes.push(...parseEmphasis(part, `${keyBase}e${i}`));
    }
  });
  return nodes;
}

const HEADING = /^(#{1,6})\s+(.*)$/;
const HR = /^\s*([-*_])(?:\s*\1){2,}\s*$/;
const FENCE = /^\s*```/;
const BLOCKQUOTE = /^>\s?(.*)$/;
const UL_ITEM = /^(\s*)[-*+]\s+(.*)$/;
const OL_ITEM = /^(\s*)(\d+)[.)]\s+(.*)$/;

/**
 * Parse the block into Ink lines. Line-oriented: one node per source line. A
 * trailing blank line is kept deliberately — when output is committed block by
 * block into `<Static>` (see App.tsx `splitSettled`), that blank is the only
 * separator between one committed block and the next.
 */
function renderBlocks(text: string): React.ReactNode[] {
  const lines = text.split("\n");
  const out: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i]!;
    const key = `l${i}`;

    // Fenced code block: emit lines verbatim with a dim gutter until it closes.
    if (FENCE.test(line)) {
      i++;
      const code: string[] = [];
      while (i < lines.length && !FENCE.test(lines[i]!)) code.push(lines[i++]!);
      if (i < lines.length) i++; // consume closing fence
      out.push(
        <Box key={key} flexDirection="column" marginLeft={1}>
          {code.map((c, j) => (
            <Text key={j}>
              <Text dimColor>│ </Text>
              <Text color="green">{c}</Text>
            </Text>
          ))}
        </Box>,
      );
      continue;
    }

    if (line.trim() === "") {
      out.push(<Text key={key}> </Text>);
      i++;
      continue;
    }

    if (HR.test(line)) {
      out.push(
        <Text key={key} dimColor>
          ────────────────────
        </Text>,
      );
      i++;
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      out.push(
        <Text key={key} bold color="green">
          {renderInline(heading[2]!, key)}
        </Text>,
      );
      i++;
      continue;
    }

    const quote = BLOCKQUOTE.exec(line);
    if (quote) {
      out.push(
        <Text key={key}>
          <Text color="cyan">▎ </Text>
          <Text dimColor italic>
            {renderInline(quote[1]!, key)}
          </Text>
        </Text>,
      );
      i++;
      continue;
    }

    const ul = UL_ITEM.exec(line);
    if (ul) {
      const indent = " ".repeat(ul[1]!.length);
      out.push(
        <Text key={key}>
          {indent}
          <Text color="cyan">• </Text>
          {renderInline(ul[2]!, key)}
        </Text>,
      );
      i++;
      continue;
    }

    const ol = OL_ITEM.exec(line);
    if (ol) {
      const indent = " ".repeat(ol[1]!.length);
      out.push(
        <Text key={key}>
          {indent}
          <Text color="cyan">{ol[2]}. </Text>
          {renderInline(ol[3]!, key)}
        </Text>,
      );
      i++;
      continue;
    }

    out.push(<Text key={key}>{renderInline(line, key)}</Text>);
    i++;
  }

  return out;
}

/** Render Markdown text as a column of styled terminal lines. */
export function Markdown({ text }: { text: string }): React.ReactNode {
  return <Box flexDirection="column">{renderBlocks(text)}</Box>;
}
