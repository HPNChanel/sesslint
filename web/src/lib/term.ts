// Terminal rendering for captured CLI output (src/data/demo.json). Colour is
// derived from the verdict words the CLI itself prints, so a line is only
// green/amber/red when SessLint said pass/warn/fail on it.
export type Tone = "" | "p" | "w" | "e" | "i" | "m";
export type TermLine = { text: string; tone: Tone };

const RULES: readonly [RegExp, Tone][] = [
  [/\bblocked\b|\bERROR\b|\bFAIL(ED)?\b|\[SL203\]|SL102 x|SL203 x/, "e"],
  [/WARNING|with warnings|SL003 x/, "w"],
  [/\[PASS\]|PASSED|Repair successful|^ok:|repaired-lossless|^Valid |^sealed:/, "p"],
  [/^Assurance:|structural assurance|^Next (Action|steps)|^Evidence still needed/, "i"],
  [/[Ff]ingerprint|^\s*source:|Idempotency|^\s*Span:|^Manifest|Structural evidence only|native (state|registry)/, "m"],
];

export function toneOf(line: string): Tone {
  for (const [re, tone] of RULES) if (re.test(line)) return tone;
  return "";
}

/** Shorten one very long line (e.g. the 31-code coverage list) at a word boundary. */
function elide(line: string, max: number): string {
  if (line.length <= max) return line;
  const cut = line.lastIndexOf(" ", max);
  return `${line.slice(0, cut > max / 2 ? cut : max)} …`;
}

export function termLines(out: string, max = 0): TermLine[] {
  return out.split("\n").map((raw) => {
    const text = max ? elide(raw, max) : raw;
    return { text, tone: toneOf(raw) };
  });
}
