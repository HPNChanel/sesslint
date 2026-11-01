import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT, commands, detectors, packageVersion, recipes } from "../../src/lib/repo";
import { artifactName, classify, lookupRelease, normalizeGithubReleases, verificationEvidence } from "../../src/lib/releases";

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
    expect(classify("sha256sums.txt").kind).toBe("checksum");
  });

  it("distinguishes draft-only, prerelease, unpublished and unavailable release facts", () => {
    const releases = normalizeGithubReleases([
      { tag_name: "v0.5.0", html_url: "https://example.test/draft", published_at: null, draft: true, prerelease: false, assets: [] },
      { tag_name: "v0.5.0-rc.1", html_url: "https://example.test/rc", published_at: "2026-10-24T00:00:00Z", draft: false, prerelease: true, assets: [] },
    ]);
    expect(releases).toHaveLength(1);
    expect(lookupRelease("0.5.0-rc.1", releases).availability).toBe("prerelease");
    expect(lookupRelease("0.5.0", releases)).toEqual({ availability: "unpublished", release: null });
    expect(lookupRelease("0.5.0", null)).toEqual({ availability: "unknown", release: null });
  });

  it("does not invent a missing signature or asset URL", () => {
    const [release] = normalizeGithubReleases([{ tag_name: "v0.2.0", html_url: "https://example.test/0.2.0", published_at: "2026-10-01T00:00:00Z", draft: false, prerelease: false, assets: [{ name: "sha256sums.txt", browser_download_url: "https://example.test/sums", size: 12 }] }]);
    expect(release?.assets).toEqual([expect.objectContaining({ name: "sha256sums.txt", kind: "checksum" })]);
    expect(release?.assets.some((asset) => asset.kind === "signature")).toBe(false);
  });

  it("does not attach an unrelated signature to a binary", () => {
    const [release] = normalizeGithubReleases([
      {
        tag_name: "v0.2.0",
        html_url: "https://example.test/0.2.0",
        published_at: "2026-10-01T00:00:00Z",
        draft: false,
        prerelease: false,
        assets: [
          { name: "sesslint-0.2.0-linux-x86_64", browser_download_url: "https://example.test/bin", size: 12 },
          { name: "different-file.sigstore.json", browser_download_url: "https://example.test/sig", size: 12 },
        ],
      },
    ]);
    const binary = release?.assets.find((asset) => asset.kind === "binary");
    const signatures = new Map(
      release?.assets
        .filter((asset) => asset.kind === "signature")
        .map((asset) => [asset.name.replace(/\.(sigstore\.json|asc)$/, ""), asset]),
    );
    expect(binary && signatures.get(binary.name)).toBeUndefined();
  });
});

describe("verificationEvidence", () => {
  const release = (names: string[]) =>
    normalizeGithubReleases([
      {
        tag_name: "v0.6.0",
        html_url: "https://github.com/x/y/releases/tag/v0.6.0",
        published_at: "2026-10-01T00:00:00Z",
        draft: false,
        prerelease: false,
        assets: names.map((name) => ({ name, browser_download_url: `https://github.com/x/y/releases/download/v0.6.0/${name}`, size: 1 })),
      },
    ])[0]!;

  it("never offers a GPG .asc signature as a Sigstore bundle", () => {
    const ev = verificationEvidence(release(["sesslint-0.6.0-linux-x86_64", "sesslint-0.6.0-linux-x86_64.asc", "sha256sums.txt"]));
    expect(ev.binary?.name).toBe("sesslint-0.6.0-linux-x86_64");
    expect(ev.sigstore).toBeNull();
    expect(ev.checksum?.name).toBe("sha256sums.txt");
    expect(ev.provenance).toBeNull();
  });

  it("pairs the bundle that matches the binary", () => {
    const ev = verificationEvidence(
      release(["sesslint-0.6.0-linux-x86_64", "sesslint-0.6.0-linux-x86_64.asc", "sesslint-0.6.0-linux-x86_64.sigstore.json", "sesslint-provenance.intoto.jsonl"]),
    );
    expect(ev.sigstore?.name).toBe("sesslint-0.6.0-linux-x86_64.sigstore.json");
    expect(ev.provenance?.name).toBe("sesslint-provenance.intoto.jsonl");
  });

  it("reports nothing for a legacy wheel-only release", () => {
    expect(verificationEvidence(release(["sesslint-0.1.0-py3-none-any.whl", "sha256sums.txt"]))).toEqual(
      expect.objectContaining({ binary: null, sigstore: null, provenance: null }),
    );
  });
});

describe("normalizeGithubReleases on malformed metadata", () => {
  const ok = {
    tag_name: "v0.6.0",
    html_url: "https://github.com/x/y/releases/tag/v0.6.0",
    published_at: "2026-10-01T00:00:00Z",
    draft: false,
    prerelease: false,
    assets: [{ name: "sha256sums.txt", browser_download_url: "https://github.com/x/y/s", size: 1 }],
  };

  it("keeps a well-formed published record", () => {
    expect(normalizeGithubReleases([ok]).map((r) => r.availability)).toEqual(["published"]);
  });

  it.each([
    ["draft missing", { draft: undefined }],
    ["draft not boolean", { draft: "false" }],
    ["prerelease missing", { prerelease: undefined }],
    ["prerelease not boolean", { prerelease: 0 }],
    ["tag missing", { tag_name: undefined }],
    ["tag not a version", { tag_name: "nightly" }],
    ["html_url not https", { html_url: "javascript:alert(1)" }],
    ["assets missing", { assets: undefined }],
    ["asset url not https", { assets: [{ name: "x", browser_download_url: "http://example.test/x", size: 1 }] }],
    ["asset name missing", { assets: [{ browser_download_url: "https://example.test/x", size: 1 }] }],
  ])("drops a record with %s instead of presenting it as published", (_label, patch) => {
    expect(normalizeGithubReleases([ok, { ...ok, tag_name: "v0.7.0", ...patch }]).map((r) => r.version)).toEqual(["0.6.0"]);
  });

  it("rejects a non-array payload so availability becomes unknown", () => {
    expect(() => normalizeGithubReleases({ message: "API rate limit exceeded" })).toThrow(TypeError);
    expect(() => normalizeGithubReleases(null)).toThrow(TypeError);
  });
});
