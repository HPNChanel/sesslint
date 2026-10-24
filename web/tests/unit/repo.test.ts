import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT, commands, detectors, packageVersion, recipes } from "../../src/lib/repo";
import { artifactName, classify, fallbackRelease } from "../../src/lib/releases";

describe("repo facts", () => {
  it("counts detectors from docs/codes", () => {
    const files = readdirSync(join(REPO_ROOT, "docs", "codes")).filter((f) => /^SL\d{3}\.md$/.test(f));
    expect(detectors()).toHaveLength(files.length);
    expect(detectors().find((d) => d.code === "SL203")?.title).toBe("Unknown side-effect state");
    expect(detectors().find((d) => d.code === "SL203")?.group).toBe("checkpoint");
  });

  it("reads recipes, version and commands", () => {
    expect(recipes()).toContain("torn-record-excision");
    expect(packageVersion()).toMatch(/^\d+\.\d+\.\d+/);
    const triage = commands().find((c) => c.name === "triage");
    expect(triage?.access).toBe("read-only");
    expect(triage?.summary).toMatch(/^Diagnose a session/);
  });
});

describe("release assets", () => {
  it("matches scripts/package.py naming", () => {
    expect(artifactName("0.4.0", "windows", "x86_64")).toBe("sesslint-0.4.0-windows-x86_64.exe");
    expect(classify("sesslint-0.4.0-macos-arm64")).toEqual({ kind: "binary", os: "macos", arch: "arm64" });
    expect(classify("sesslint-0.4.0-linux-x86_64.sigstore.json").kind).toBe("signature");
    expect(fallbackRelease("0.4.0").assets.filter((a) => a.kind === "binary")).toHaveLength(3);
  });
});
