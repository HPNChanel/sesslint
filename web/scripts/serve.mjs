// Minimal static server for e2e: serves dist/ under the site base the way
// GitHub Pages does (directory index.html, 404.html with status 404).
// Usage: node scripts/serve.mjs [port]
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist/", import.meta.url));
const base = (process.env.SITE_BASE ?? "/sesslint").replace(/\/$/, "");
const port = Number(process.argv[2] ?? 4322);
const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".xml": "application/xml",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".txt": "text/plain; charset=utf-8",
};

function resolve(urlPath) {
  if (!urlPath.startsWith(`${base}/`) && urlPath !== base) return null;
  const rel = normalize(decodeURIComponent(urlPath.slice(base.length))).replace(/^([/\\])+/, "");
  if (rel.startsWith("..")) return null;
  let file = join(root, rel);
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, "index.html");
  return existsSync(file) ? file : null;
}

createServer((req, res) => {
  const path = new URL(req.url ?? "/", "http://x").pathname;
  if (path === base) {
    res.writeHead(301, { Location: `${base}/` }).end();
    return;
  }
  const file = resolve(path);
  const target = file ?? join(root, "404.html");
  res.writeHead(file ? 200 : 404, { "Content-Type": types[extname(target)] ?? "application/octet-stream" });
  createReadStream(target).pipe(res);
}).listen(port, () => console.log(`serving dist/ at http://localhost:${port}${base}/`));
