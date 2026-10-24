// Build-time readers for facts that already live in the repository, so the
// site never restates a number by hand (detector count, version, commands).
// Read-only: nothing here executes repository code.
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

export const REPO_ROOT = resolve(process.env.SESSLINT_REPO_ROOT ?? join(process.cwd(), ".."));
export const REPO_SLUG = "HPNChanel/sesslint";
export const REPO_URL = `https://github.com/${REPO_SLUG}`;

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), "utf8");
}

/** Same pattern as scripts/package.py:package_version. */
export function packageVersion(): string {
  const m = /__version__\s*=\s*"([^"]+)"/.exec(read("src/sesslint/_version.py"));
  if (!m?.[1]) throw new Error("could not parse __version__ from src/sesslint/_version.py");
  return m[1];
}

export function readChangelogSource(): string {
  return read("CHANGELOG.md");
}

export type DetectorGroup = {
  id: string;
  label: string;
  range: [number, number];
};

/** Category bands mirror the README "Detector codes" grouping. */
export const DETECTOR_GROUPS: readonly DetectorGroup[] = [
  { id: "syntax", label: "Syntax & framing", range: [1, 2] },
  { id: "identity", label: "Event identity", range: [3, 3] },
  { id: "graph", label: "Graph lineage", range: [4, 99] },
  { id: "pairing", label: "Tool call/result pairing", range: [101, 199] },
  { id: "checkpoint", label: "Checkpoints & continuation", range: [201, 299] },
  { id: "compat", label: "Format & cross-file", range: [301, 499] },
];

export type Detector = {
  code: string;
  title: string;
  group: string;
  num: number;
  severity: string;
  repairability: string;
};

/** Value of a `- **Key**: \`value\`` overview bullet, as the docs write them. */
function field(md: string, key: string): string {
  const m = new RegExp("^- \\*\\*" + key + "\\*\\*:\\s*`?([^`\\n]+)`?", "m").exec(md);
  return m?.[1]?.trim() ?? "";
}

export function detectorGroupOf(num: number): string {
  const g = DETECTOR_GROUPS.find((d) => num >= d.range[0] && num <= d.range[1]);
  return g ? g.id : "compat";
}

export function detectors(): Detector[] {
  const dir = join(REPO_ROOT, "docs", "codes");
  return readdirSync(dir)
    .filter((f) => /^SL\d{3}\.md$/.test(f))
    .sort()
    .map((f) => {
      const code = f.slice(0, -3);
      const num = Number(code.slice(2));
      const md = readFileSync(join(dir, f), "utf8");
      const first = md.split("\n", 1)[0] ?? "";
      const title = first.replace(/^#\s*SL\d{3}\s*[:\-–]\s*/, "").trim() || code;
      return {
        code,
        title,
        group: detectorGroupOf(num),
        num,
        severity: field(md, "Default Severity") || "error",
        repairability: field(md, "Default Repairability"),
      };
    });
}

export function recipes(): string[] {
  return readdirSync(join(REPO_ROOT, "docs", "recipes"))
    .filter((f) => f.endsWith(".md") && f !== "README.md")
    .map((f) => f.slice(0, -3))
    .sort();
}

export type Recipe = { id: string; codes: string[]; lossy: boolean; salvage: boolean };

export function recipeInfo(): Recipe[] {
  const dir = join(REPO_ROOT, "docs", "recipes");
  return recipes().map((id) => {
    const md = readFileSync(join(dir, `${id}.md`), "utf8");
    return {
      id,
      codes: field(md, "Handles Codes").match(/SL\d{3}/g) ?? [],
      lossy: field(md, "Lossy") === "true",
      salvage: field(md, "Salvage Only") === "true",
    };
  });
}

export type Command = { name: string; summary: string; access: string };

/** Unescape the small roff subset man pages use (`\-`). */
function roff(s: string): string {
  return s.replace(/\\-/g, "-").replace(/\\\(em/g, "—").trim();
}

export function commands(): Command[] {
  const dir = join(REPO_ROOT, "man");
  return readdirSync(dir)
    .filter((f) => /^sesslint-[a-z]+\.1$/.test(f))
    .sort()
    .map((f) => {
      const text = readFileSync(join(dir, f), "utf8");
      const nameLine = /\.SH NAME\r?\n(.+)/.exec(text)?.[1] ?? "";
      const body = roff(nameLine.replace(/^\S+\s+\\-\s*/, ""));
      const access = /^\[([^\]]+)\]/.exec(body)?.[1] ?? "";
      return {
        name: f.replace(/^sesslint-/, "").replace(/\.1$/, ""),
        summary: body.replace(/^\[[^\]]+\]\s*/, ""),
        access,
      };
    });
}
