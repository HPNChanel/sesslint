// Renders public/og.png (1200×630 social preview) with Playwright's Chromium.
// Run after changing the design: `npm run og`. The PNG is committed so the
// site build itself never needs a browser.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const font = (p) => `data:font/woff2;base64,${readFileSync(join(root, "node_modules", p)).toString("base64")}`;
const mono = font("@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2");
const monoBold = font("@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-600-normal.woff2");
const display = font("@fontsource-variable/fraunces/files/fraunces-latin-opsz-normal.woff2");

const html = `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: Mono; src: url(${mono}); font-weight: 400; }
@font-face { font-family: Mono; src: url(${monoBold}); font-weight: 600; }
@font-face { font-family: Display; src: url(${display}); font-weight: 100 900; }
* { box-sizing: border-box; margin: 0; }
body { width: 1200px; height: 630px; background: #0b0d0c; color: #e8e4d8; font-family: Mono;
  background-image: repeating-linear-gradient(#0b0d0c 0 31px, #1a1e1c 31px 32px); position: relative; overflow: hidden; }
.margin { position: absolute; left: 96px; top: 0; bottom: 0; width: 2px; background: #ff5a4e; opacity: .7; }
.man { position: absolute; top: 40px; left: 128px; right: 72px; display: flex; justify-content: space-between; font-size: 20px; color: #8a8f8a; }
h1 { position: absolute; left: 128px; top: 150px; width: 900px; font-family: Display; font-weight: 500; font-size: 78px; line-height: 1.02; letter-spacing: -1.5px; }
.cmd { position: absolute; left: 128px; top: 400px; font-size: 30px; padding: 16px 24px; border: 2px solid #3a3f3c; background: #121513; }
.cmd b { color: #9be564; }
.tags { position: absolute; left: 128px; bottom: 56px; display: flex; gap: 28px; font-size: 21px; color: #b8b4a8; }
.tags span::before { content: "✓ "; color: #9be564; }
.verdict { position: absolute; right: 72px; top: 400px; text-align: right; font-size: 22px; line-height: 1.6; }
.p { color: #9be564; } .w { color: #ffb224; } .e { color: #ff5a4e; }
</style></head><body>
<div class="margin"></div>
<div class="man"><span>SESSLINT(1)</span><span>SessLint Manual</span><span>SESSLINT(1)</span></div>
<h1>Find what broke in an agent session.</h1>
<div class="cmd"><b>❯</b> pipx install sesslint</div>
<div class="verdict"><div class="w">[SL003] duplicate event</div><div class="e">[SL203] refused · exit 1</div><div class="p">verify: PASSED · lossless</div></div>
<div class="tags"><span>0 runtime deps</span><span>offline only</span><span>Apache-2.0</span><span>Sigstore + SLSA</span></div>
</body></html>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.setContent(html);
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: join(root, "public", "og.png") });
await browser.close();
console.log("wrote public/og.png");
