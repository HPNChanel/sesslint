import { describe, expect, it } from "vitest";
import demo from "../../src/data/demo.json";
import { termLines, toneOf } from "../../src/lib/term";

describe("toneOf", () => {
  it("colours lines by the verdict the CLI printed", () => {
    expect(toneOf("Verification: PASSED")).toBe("p");
    expect(toneOf("  [PASS] source_hash: matched")).toBe("p");
    expect(toneOf("  [SL003] Duplicate event ID (WARNING, deterministic)")).toBe("w");
    expect(toneOf("SessLint triage: blocked")).toBe("e");
    expect(toneOf("Assurance: A2 - replay not exercised")).toBe("i");
    expect(toneOf("Output fingerprint: abc")).toBe("m");
    expect(toneOf("plain text")).toBe("");
  });
});

describe("termLines", () => {
  it("keeps every line and elides only long ones", () => {
    const out = demo.steps.check.out;
    const lines = termLines(out, 96);
    expect(lines).toHaveLength(out.split("\n").length);
    for (const l of lines) expect(l.text.length).toBeLessThanOrEqual(98);
    expect(lines.some((l) => l.text.endsWith("…"))).toBe(true);
  });

  it("captured refusal really is a refusal", () => {
    expect(demo.steps.refuse.exit).not.toBe(0);
    expect(termLines(demo.steps.refuse.out).some((l) => l.tone === "e")).toBe(true);
  });
});
