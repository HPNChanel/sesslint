// Build-time GitHub Releases lookup. Asset links are rendered only when
// GitHub returned them for a non-draft release; URLs are never inferred.
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
  availability: "published" | "prerelease";
};
export type ReleaseAvailability = "published" | "prerelease" | "unpublished" | "unknown";
export type ReleaseLookup =
  | { availability: "published" | "prerelease"; release: ReleaseInfo }
  | { availability: "unpublished" | "unknown"; release: null };

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

export type GithubReleasePayload = { tag_name: string; html_url: string; published_at: string | null; draft: boolean; prerelease: boolean; assets: { name: string; browser_download_url: string; size: number; digest?: string | null }[] };

type GithubResult = { available: true; releases: ReleaseInfo[] } | { available: false; releases: [] };
let cache: Promise<GithubResult> | null = null;

const isHttps = (v: unknown): v is string => {
  if (typeof v !== "string") return false;
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
};

type GithubAssetPayload = GithubReleasePayload["assets"][number];

function validAsset(a: unknown): a is GithubAssetPayload {
  if (typeof a !== "object" || a === null) return false;
  const x = a as Record<string, unknown>;
  return typeof x.name === "string" && x.name !== "" && isHttps(x.browser_download_url) && typeof x.size === "number"
    && (x.digest === undefined || x.digest === null || typeof x.digest === "string");
}

/**
 * Fail closed on malformed metadata: a record counts only when it is
 * explicitly `draft: false` with a boolean `prerelease`, a tag, HTTPS URLs
 * and well-formed assets. Anything else is dropped rather than presented as
 * a download. A non-array payload throws (the caller reports "unknown").
 */
function validRelease(r: unknown): r is GithubReleasePayload {
  if (typeof r !== "object" || r === null) return false;
  const x = r as Record<string, unknown>;
  return x.draft === false && typeof x.prerelease === "boolean"
    && typeof x.tag_name === "string" && /^v?\d+\.\d+\.\d+/.test(x.tag_name)
    && isHttps(x.html_url)
    && (x.published_at === null || typeof x.published_at === "string")
    && Array.isArray(x.assets) && x.assets.every(validAsset);
}

/** Normalize only non-draft API records; prereleases remain distinct from published releases. */
export function normalizeGithubReleases(data: unknown): ReleaseInfo[] {
  if (!Array.isArray(data)) throw new TypeError("GitHub releases payload is not an array");
  return data.filter(validRelease).map((r) => ({
    tag: r.tag_name,
    version: r.tag_name.replace(/^v/, ""),
    publishedAt: r.published_at,
    url: r.html_url,
    availability: r.prerelease ? "prerelease" as const : "published" as const,
    assets: r.assets.map((a) => ({
      name: a.name, url: a.browser_download_url, size: a.size,
      sha256: a.digest?.startsWith("sha256:") ? a.digest.slice(7) : null,
      ...classify(a.name),
    })).sort((x, y) => x.name.localeCompare(y.name)),
  }));
}

export function lookupRelease(version: string, releases: ReleaseInfo[] | null): ReleaseLookup {
  if (releases === null) return { availability: "unknown", release: null };
  const release = releases.find((r) => r.version === version);
  return release ? { availability: release.availability, release } : { availability: "unpublished", release: null };
}

async function fetchReleases(): Promise<GithubResult> {
  if (process.env.SESSLINT_WEB_OFFLINE === "1") return { available: false, releases: [] };
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
    if (!res.ok) return { available: false, releases: [] };
    const data: unknown = await res.json();
    return { available: true, releases: normalizeGithubReleases(data) };
  } catch {
    return { available: false, releases: [] };
  }
}

/** Actual non-draft GitHub releases, including prereleases, newest first. */
export function githubReleases(): Promise<GithubResult> {
  cache ??= fetchReleases();
  return cache;
}

/** A changelog entry is not itself proof that GitHub published a release. */
export async function releaseFor(version: string): Promise<ReleaseLookup> {
  const result = await githubReleases();
  return lookupRelease(version, result.available ? result.releases : null);
}

/** Evidence files a release actually lists, keyed for the verify commands. */
export type VerificationEvidence = {
  /** First binary; the cosign and slsa-verifier commands target it. */
  binary: Asset | null;
  checksum: Asset | null;
  /** Sigstore bundle for `binary`. A detached `.asc` (GPG) signature is not one. */
  sigstore: Asset | null;
  provenance: Asset | null;
};

export function verificationEvidence(release: ReleaseInfo): VerificationEvidence {
  const binary = release.assets.find((a) => a.kind === "binary" && a.os !== undefined) ?? null;
  const checksum = release.assets.find((a) => a.kind === "checksum" && /^sha256sums\.txt$/i.test(a.name)) ?? null;
  const sigstore = binary ? (release.assets.find((a) => a.name === `${binary.name}.sigstore.json`) ?? null) : null;
  const provenance = release.assets.find((a) => a.kind === "provenance") ?? null;
  return { binary, checksum, sigstore, provenance };
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
