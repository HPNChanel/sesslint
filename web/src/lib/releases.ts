// Build-time GitHub Releases lookup for the Download page. Falls back to the
// deterministic asset naming in scripts/package.py when the API is
// unreachable (offline builds, rate limits) so the build never fails on it.
import { REPO_SLUG } from "./repo";

export type Asset = {
  name: string;
  url: string;
  size: number | null;
  sha256: string | null;
  kind: "binary" | "kit" | "checksum" | "signature" | "provenance" | "other";
  os?: "linux" | "macos" | "windows";
  arch?: string;
};

export type ReleaseInfo = {
  tag: string;
  version: string;
  publishedAt: string | null;
  url: string;
  assets: Asset[];
  source: "github" | "fallback";
};

/** Platforms the release workflow builds (ubuntu-22.04, windows, macos). */
const FALLBACK_PLATFORMS = [
  { os: "linux", arch: "x86_64" },
  { os: "windows", arch: "x86_64" },
  { os: "macos", arch: "arm64" },
] as const;

export function artifactName(version: string, os: string, arch: string): string {
  return `sesslint-${version}-${os}-${arch}${os === "windows" ? ".exe" : ""}`;
}

export function classify(name: string): Pick<Asset, "kind" | "os" | "arch"> {
  if (name.endsWith(".sigstore.json") || name.endsWith(".asc")) return { kind: "signature" };
  if (name.includes("provenance")) return { kind: "provenance" };
  if (/sha256sums|SHA256SUMS|artifact-manifest/.test(name)) return { kind: "checksum" };
  const bin = /^sesslint-[\w.+-]+?-(linux|macos|windows)-(x86_64|arm64|aarch64)(\.exe)?$/.exec(name);
  if (bin) return { kind: "binary", os: bin[1] as Asset["os"] & string, arch: bin[2] ?? "" };
  if (/\.(zip|tar\.gz)$/.test(name)) return { kind: "kit" };
  return { kind: "other" };
}

export function fallbackRelease(version: string): ReleaseInfo {
  const tag = `v${version}`;
  const dl = `https://github.com/${REPO_SLUG}/releases/download/${tag}`;
  const names = [
    ...FALLBACK_PLATFORMS.map((p) => artifactName(version, p.os, p.arch)),
    `sesslint-${version}-starter-kit.zip`,
    `sesslint-${version}-man.tar.gz`,
    "sha256sums.txt",
    "sesslint-provenance.intoto.jsonl",
  ];
  return {
    tag,
    version,
    publishedAt: null,
    url: `https://github.com/${REPO_SLUG}/releases/tag/${tag}`,
    source: "fallback",
    assets: names.map((name) => ({ name, url: `${dl}/${name}`, size: null, sha256: null, ...classify(name) })),
  };
}

type GhAsset = { name: string; browser_download_url: string; size: number; digest?: string | null };
type GhRelease = { tag_name: string; html_url: string; published_at: string | null; draft: boolean; assets: GhAsset[] };

let cache: Promise<ReleaseInfo[]> | null = null;

async function fetchReleases(): Promise<ReleaseInfo[]> {
  if (process.env.SESSLINT_WEB_OFFLINE === "1") return [];
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "sesslint-web-build",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    const res = await fetch(`https://api.github.com/repos/${REPO_SLUG}/releases?per_page=20`, {
      headers,
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as GhRelease[];
    return data
      .filter((r) => !r.draft)
      .map((r) => ({
        tag: r.tag_name,
        version: r.tag_name.replace(/^v/, ""),
        publishedAt: r.published_at,
        url: r.html_url,
        source: "github" as const,
        assets: r.assets
          .map((a) => ({
            name: a.name,
            url: a.browser_download_url,
            size: a.size,
            sha256: a.digest?.startsWith("sha256:") ? a.digest.slice(7) : null,
            ...classify(a.name),
          }))
          .sort((x, y) => x.name.localeCompare(y.name)),
      }));
  } catch {
    return [];
  }
}

/** Published releases, newest first; [] when the API is unavailable. */
export function githubReleases(): Promise<ReleaseInfo[]> {
  cache ??= fetchReleases();
  return cache;
}

/** Release info for `version`, from GitHub when available, else synthesized. */
export async function releaseFor(version: string): Promise<ReleaseInfo> {
  const found = (await githubReleases()).find((r) => r.version === version);
  return found ?? fallbackRelease(version);
}

export function humanSize(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}
