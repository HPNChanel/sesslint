// Build the mkdocs site into dist/docs/ with site_url taken from SITE_URL
// (site.config.mjs), so a custom domain needs no edit to mkdocs.yml.
// mkdocs.yml stays plain YAML; the override is a throwaway INHERIT file.
// Usage: node scripts/build_docs.mjs   (needs uv and the docs extra)
import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { siteLocation } from "../site.config.mjs";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const override = `${repo}.mkdocs.site.yml`;
const docsUrl = `${siteLocation().url}/docs/`;

writeFileSync(override, `INHERIT: mkdocs.yml\nsite_url: ${docsUrl}\n`);
try {
  const run = spawnSync(
    "uv",
    ["run", "--project", repo, "mkdocs", "build", "--quiet", "--config-file", override, "--site-dir", "web/dist/docs"],
    { cwd: repo, stdio: "inherit", shell: process.platform === "win32" },
  );
  if (run.status !== 0) process.exit(run.status ?? 1);
  console.log(`docs built for ${docsUrl}`);
} finally {
  rmSync(override, { force: true });
}
