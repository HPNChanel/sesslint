import { describe, expect, it } from "vitest";
import { GENESIS, compareVersions, headlineOf, parseChangelog } from "../../src/lib/changelog";
import { readChangelogSource } from "../../src/lib/repo";

const SAMPLE = `# Changelog

## [Unreleased]

### Changed (0.5.0 breaking CLI)

- \`scan\` is now an alias of \`check\`; directory inputs
  are always recursive.

## [1.1.0] - 2026-02-02

Intro paragraph.

### Added

- **New thing** (T-1): with details.
- Plain entry. More text.

### Fixed

- A fix.

## [1.0.0] - 2026-01-01

### Added

- First.

[Unreleased]: https://example.invalid/compare
[1.1.0]: https://example.invalid/1.1.0
`;

describe("parseChangelog", () => {
  const rels = parseChangelog(SAMPLE);

  it("reads releases newest first with dates", () => {
    expect(rels.map((r) => [r.version, r.date])).toEqual([
      ["Unreleased", null],
      ["1.1.0", "2026-02-02"],
      ["1.0.0", "2026-01-01"],
    ]);
  });

  it("joins continuation lines and flags breaking sections", () => {
    const sec = rels[0]?.sections[0];
    expect(sec?.kind).toBe("Changed");
    expect(sec?.breaking).toBe(true);
    expect(sec?.entries[0]?.markdown).toBe("`scan` is now an alias of `check`; directory inputs are always recursive.");
    expect(sec?.entries[0]?.breaking).toBe(true);
  });

  it("captures intros and ignores link references", () => {
    expect(rels[1]?.intro).toBe("Intro paragraph.");
    expect(rels[1]?.sections.map((s) => [s.kind, s.entries.length])).toEqual([
      ["Added", 2],
      ["Fixed", 1],
    ]);
    expect(rels[2]?.raw).not.toContain("example.invalid");
  });

  it("chains display hashes oldest to newest; Unreleased stays unsealed", () => {
    const [unrel, v11, v10] = rels;
    expect(v10?.prev).toBe(GENESIS);
    expect(v11?.prev).toBe(v10?.hash);
    expect(unrel?.prev).toBe(v11?.hash);
    expect(unrel?.hash).toBeNull();
    expect(v11?.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(parseChangelog(SAMPLE)[1]?.hash).toBe(v11?.hash);
  });
});

describe("headlineOf", () => {
  it("prefers the leading bold run", () => {
    expect(headlineOf("**`sesslint seal` ledger** (T-01): long")).toBe("sesslint seal ledger");
  });
  it("falls back to the first sentence", () => {
    expect(headlineOf("Plain entry. More text.")).toBe("Plain entry");
  });
});

describe("compareVersions", () => {
  it("orders numerically", () => {
    expect(compareVersions("v0.10.0", "0.9.9")).toBeGreaterThan(0);
    expect(compareVersions("0.4.0", "v0.4.0")).toBe(0);
  });
});

describe("real CHANGELOG.md", () => {
  const real = parseChangelog(readChangelogSource());
  it("has Unreleased and every tagged release with a date", () => {
    expect(real[0]?.unreleased).toBe(true);
    const dated = real.filter((r) => !r.unreleased);
    expect(dated.map((r) => r.version)).toEqual(expect.arrayContaining(["0.4.0", "0.3.0", "0.2.0", "0.1.0"]));
    for (const r of dated) expect(r.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
  it("detects the 0.5.0 breaking CLI section", () => {
    expect(real.some((r) => r.sections.some((s) => s.breaking))).toBe(true);
  });
  it("every section has entries", () => {
    for (const r of real) for (const s of r.sections) expect(s.entries.length).toBeGreaterThan(0);
  });
});
