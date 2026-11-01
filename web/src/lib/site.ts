// Facts shared by every page, computed once per build.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseChangelog, released, type Release } from "./changelog";
import { REPO_ROOT, packageVersion, readChangelogSource } from "./repo";
import { githubReleases, type ReleaseInfo } from "./releases";

function gitShort(): string {
  const env = process.env.GITHUB_SHA;
  if (env) return env.slice(0, 7);
  try {
    const head = readFileSync(join(REPO_ROOT, ".git", "HEAD"), "utf8").trim();
    if (!head.startsWith("ref:")) return head.slice(0, 7);
    const ref = head.slice(5).trim();
    try {
      return readFileSync(join(REPO_ROOT, ".git", ref), "utf8").trim().slice(0, 7);
    } catch {
      const packed = readFileSync(join(REPO_ROOT, ".git", "packed-refs"), "utf8");
      const line = packed.split("\n").find((l) => l.endsWith(` ${ref}`));
      return line ? line.slice(0, 7) : "local";
    }
  } catch {
    return "local";
  }
}

let memo: SiteFacts | null = null;
let publicationMemo: Promise<{ available: boolean; releases: ReleaseInfo[]; latest: ReleaseInfo | null }> | null = null;

export type SiteFacts = {
  /** Releases worth rendering: an empty Unreleased block is dropped. */
  releases: Release[];
  latest: Release | null;
  packageVersion: string;
  build: string;
};

export function site(): SiteFacts {
  if (memo) return memo;
  const releases = parseChangelog(readChangelogSource()).filter((r) => !r.unreleased || r.sections.length > 0);
  memo = {
    releases,
    latest: released(releases)[0] ?? null,
    packageVersion: packageVersion(),
    build: gitShort(),
  };
  return memo;
}

/** Actual published GitHub releases only; changelog dates never establish publication. */
export function publishedSite(): Promise<{ available: boolean; releases: ReleaseInfo[]; latest: ReleaseInfo | null }> {
  publicationMemo ??= githubReleases().then((result) => {
    const releases = result.available ? result.releases.filter((r) => r.availability === "published") : [];
    return { available: result.available, releases, latest: releases[0] ?? null };
  });
  return publicationMemo;
}
