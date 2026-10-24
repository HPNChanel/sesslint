// Internal link check over the built site (dist/, including mkdocs at
// dist/docs/ when present). Every href/src that stays on the site must hit a
// file, and every #fragment on an Astro page must hit an id. External links
// are not fetched: the check is offline and deterministic.
// Usage: node scripts/check_links.mjs   (after `npm run build`)
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { siteLocation } from "../site.config.mjs";

const root = fileURLToPath(new URL("../dist/", import.meta.url));
const { origin, prefix } = siteLocation();
const ORIGIN = `${origin}${prefix}/`;

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (name.endsWith(".html")) yield p;
  }
}

/** dist file → its public URL on the site. */
function urlOf(file) {
  const rel = relative(root, file).split(sep).join("/");
  return new URL(rel.replace(/(^|\/)index\.html$/, "$1"), ORIGIN);
}

/** Public URL → dist file, the way GitHub Pages resolves it. */
function fileOf(url) {
  if (url.origin !== origin || !`${url.pathname}/`.startsWith(`${prefix}/`)) return null;
  let rel = decodeURIComponent(url.pathname.slice(prefix.length)).replace(/^\/+/, "");
  const direct = join(root, rel);
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  else if (existsSync(direct) && statSync(direct).isDirectory()) rel += "/index.html";
  const file = join(root, rel);
  return existsSync(file) ? file : undefined;
}

const ids = new Map();
function idsOf(file) {
  if (!ids.has(file)) {
    const html = readFileSync(file, "utf8");
    ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return ids.get(file);
}

const ATTR = /\s(?:href|src)="([^"]*)"/g;
const SKIP = /^(?:[a-z][a-z0-9+.-]*:|\/\/|#$|$)/i; // other schemes, protocol-relative, bare #
const broken = [];
let pages = 0;
let links = 0;

for (const file of walk(root)) {
  pages += 1;
  const html = readFileSync(file, "utf8");
  const page = urlOf(file);
  const isDocs = page.pathname.startsWith(`${prefix}/docs/`);
  for (const [, raw] of html.matchAll(ATTR)) {
    const ref = raw.replaceAll("&amp;", "&");
    if (SKIP.test(ref) && !ref.startsWith(ORIGIN) && !ref.startsWith(origin)) continue;
    links += 1;
    const url = new URL(ref, page);
    const target = url.pathname === page.pathname && !ref.startsWith("http") ? file : fileOf(url);
    if (target === null) continue; // same host, outside the site (e.g. another Pages project)
    const where = `${relative(root, file)} → ${ref}`;
    if (!target) {
      broken.push(`missing: ${where}`);
      continue;
    }
    // mkdocs validates its own anchors; check fragments on Astro pages only.
    const frag = url.hash.slice(1);
    if (frag && !isDocs && target.endsWith(".html") && !idsOf(target).has(decodeURIComponent(frag))) {
      broken.push(`no #${frag}: ${where}`);
    }
  }
}

if (!existsSync(join(root, "docs", "index.html"))) {
  console.warn("note: dist/docs/ not built; links into /docs/ are reported missing. Run mkdocs first.");
}
if (broken.length) {
  console.error(broken.join("\n"));
  console.error(`\n${broken.length} broken link(s) across ${pages} pages`);
  process.exit(1);
}
console.log(`ok: ${links} internal links across ${pages} pages under ${ORIGIN}`);
