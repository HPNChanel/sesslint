import { site } from "./site";

/** getStaticPaths for /changelog/[version]: every release plus "unreleased". */
export function releasePaths() {
  return site().releases.map((release) => ({
    params: { version: release.unreleased ? "unreleased" : release.version },
    props: { release },
  }));
}
