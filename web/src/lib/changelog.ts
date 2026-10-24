// Keep a Changelog parser for CHANGELOG.md, the single source of truth for
// the /changelog page and its feeds. Released blocks are chained with a
// display hash (sha256 of the previous hash + the block), echoing
// `sesslint seal`. It is presentation only, not a signature.
import { createHash } from "node:crypto";

export const SECTION_KINDS = [
  "Added",
  "Changed",
  "Deprecated",
  "Removed",
  "Fixed",
  "Security",
  "Notes",
] as const;
export type SectionKind = (typeof SECTION_KINDS)[number] | "Other";

export type Entry = {
  /** Markdown of the whole bullet, continuation lines joined. */
  markdown: string;
  /** Short plain-text headline: the leading bold run or first sentence. */
  headline: string;
  breaking: boolean;
};

export type Section = { kind: SectionKind; note: string; breaking: boolean; entries: Entry[] };

export type Release = {
  version: string;
  /** ISO date, or null for Unreleased. */
  date: string | null;
  unreleased: boolean;
  intro: string;
  sections: Section[];
  /** Display hash of this block; null for the unsealed Unreleased block. */
  hash: string | null;
  prev: string;
  raw: string;
};

export const GENESIS = "0".repeat(64);

const VERSION_RE = /^## \[([^\]]+)\](?:\s*-\s*(\d{4}-\d{2}-\d{2}))?\s*$/;
const SECTION_RE = /^### ([A-Za-z]+)\s*(?:\((.+)\))?\s*$/;
const LINKREF_RE = /^\[[^\]]+\]:\s+\S+/;

function stripMd(s: string): string {
  return s
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

export function headlineOf(markdown: string): string {
  const bold = /^\*\*(.+?)\*\*/.exec(markdown);
  if (bold?.[1]) return stripMd(bold[1]).replace(/[.:]$/, "");
  const plain = stripMd(markdown);
  const cut = plain.search(/(?<=[a-z0-9`)])[.;:](\s|$)/i);
  const first = cut > 0 ? plain.slice(0, cut) : plain;
  return first.length > 140 ? `${first.slice(0, 137).trimEnd()}…` : first;
}

function isBreaking(text: string): boolean {
  return /\bbreaking\b/i.test(text);
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Parse CHANGELOG.md text. Returns releases newest-first, as written. */
export function parseChangelog(text: string): Release[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const releases: Release[] = [];
  let rel: Release | null = null;
  let sec: Section | null = null;
  let entry: string[] | null = null;
  let rawLines: string[] = [];

  const flushEntry = () => {
    if (entry && sec) {
      const markdown = entry.join(" ").replace(/\s+/g, " ").trim();
      sec.entries.push({
        markdown,
        headline: headlineOf(markdown),
        breaking: sec.breaking || isBreaking(markdown.slice(0, 200)),
      });
    }
    entry = null;
  };
  const flushRelease = () => {
    flushEntry();
    if (rel) {
      rel.raw = rawLines.join("\n").trim();
      rel.intro = rel.intro.trim();
      releases.push(rel);
    }
    rel = null;
    sec = null;
    rawLines = [];
  };

  for (const line of lines) {
    const v = VERSION_RE.exec(line);
    if (v) {
      flushRelease();
      const version = v[1] ?? "";
      const unreleased = version.toLowerCase() === "unreleased";
      rel = {
        version: unreleased ? "Unreleased" : version,
        date: v[2] ?? null,
        unreleased,
        intro: "",
        sections: [],
        hash: null,
        prev: GENESIS,
        raw: "",
      };
      continue;
    }
    if (!rel) continue;
    if (LINKREF_RE.test(line)) continue;
    rawLines.push(line);

    const s = SECTION_RE.exec(line);
    if (s) {
      flushEntry();
      const name = s[1] ?? "";
      const note = s[2] ?? "";
      const kind = (SECTION_KINDS as readonly string[]).includes(name)
        ? (name as SectionKind)
        : "Other";
      sec = { kind, note, breaking: isBreaking(note), entries: [] };
      (rel as Release).sections.push(sec);
      continue;
    }
    if (/^- /.test(line)) {
      flushEntry();
      if (!sec) {
        sec = { kind: "Other", note: "", breaking: false, entries: [] };
        (rel as Release).sections.push(sec);
      }
      entry = [line.slice(2)];
      continue;
    }
    if (entry && /^\s+\S/.test(line)) {
      entry.push(line.trim());
      continue;
    }
    if (line.trim() === "") continue;
    if (!sec) (rel as Release).intro += `${line.trim()} `;
  }
  flushRelease();
  return seal(releases);
}

/** Chain released blocks oldest → newest; Unreleased points at the head. */
function seal(releases: Release[]): Release[] {
  let prev = GENESIS;
  for (let i = releases.length - 1; i >= 0; i--) {
    const r = releases[i] as Release;
    r.prev = prev;
    if (r.unreleased) continue;
    r.hash = sha256(`${prev}\n${r.version}\n${r.date ?? ""}\n${r.raw}`);
    prev = r.hash;
  }
  return releases;
}

export function released(releases: Release[]): Release[] {
  return releases.filter((r) => !r.unreleased);
}

export function entryCount(r: Release): number {
  return r.sections.reduce((n, s) => n + s.entries.length, 0);
}

export function slug(version: string): string {
  return version.toLowerCase().replace(/[^a-z0-9.]+/g, "-");
}

export { compareVersions } from "./version";
