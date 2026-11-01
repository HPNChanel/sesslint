# SessLint website

Static Astro site: landing, download, pricing, checkout summary, rule catalog
and a changelog generated from `../CHANGELOG.md`. English at `/`, Vietnamese
under `/vi/`. The mkdocs docs are built into `/docs/` of the same artifact.

Build-time tooling only. Nothing here ships in the wheel or sdist, nothing is
imported by `src/sesslint`, and the site sets no cookies and runs no
analytics. Its only client-side request reads the public
`releases/latest` endpoint of the GitHub API.

## Develop

```bash
npm ci
npm run dev                 # http://localhost:4321/sesslint/
```

Run all gates in this order (CI does the same in `.github/workflows/docs.yml`):

```bash
npm run check               # astro check: strict TypeScript, i18n keys complete
npm test                    # vitest: pricing, checkout, changelog, repo parsing
npm run build               # dist/ (set SESSLINT_WEB_OFFLINE=1 to skip the GitHub API)
npm run docs                # mkdocs into dist/docs/ (needs uv + the docs extra)
npm run links               # every internal href/src and #fragment resolves
npm run test:e2e            # Playwright + axe against dist/, served like Pages
```

`npm run demo` recaptures the landing replay (`src/data/demo.json`) from the
CLI in this checkout, against synthetic fixtures. CI runs it on every build.

## Domain

One setting decides where the site lives: `SITE_URL`, the full public URL
(`site.config.mjs`). Astro's `site`/`base`, canonical and hreflang links, the
sitemap, robots.txt, the feeds, the mkdocs `site_url`, the e2e server and the
Playwright base URL all derive from it.

| `SITE_URL` | Served at |
| --- | --- |
| unset | `https://hpnchanel.github.io/sesslint/` (GitHub Pages project URL) |
| `https://sesslint.example` | `https://sesslint.example/` (custom domain at the root) |

To move to a custom domain:

1. **DNS.** For an apex domain, add `A` records to `185.199.108.153`,
   `185.199.109.153`, `185.199.110.153` and `185.199.111.153` (optionally
   `AAAA` to `2606:50c0:8000::153` … `2606:50c0:8003::153`). For a subdomain
   such as `www`, add a `CNAME` to `hpnchanel.github.io`.
2. **Verify the domain** for the account (GitHub → Settings → Pages →
   Verified domains) so no other repository can claim it.
3. **Repository variable:** Settings → Secrets and variables → Actions →
   Variables → `SITE_URL` = `https://sesslint.example` (no trailing slash).
4. **Pages:** Settings → Pages → Source "GitHub Actions" → Custom domain
   `sesslint.example`, then tick "Enforce HTTPS" once the certificate is
   issued. Deploys from Actions need no `CNAME` file.
5. Re-run the `docs` workflow (Actions → docs → Run workflow).

Check a build for the new domain locally before switching:

```bash
SITE_URL=https://sesslint.example npm run build && SITE_URL=https://sesslint.example npm run docs
SITE_URL=https://sesslint.example npm run links
SITE_URL=https://sesslint.example npm run test:e2e
```

## Payments

The public site is a static preview. All provider links remain inert, including
when `PUBLIC_CHECKOUT_*` variables are supplied; setting a URL does not activate
payments. Plus is USD 9 and Max USD 49, perpetual for major v1 with 1.x updates.
Pro pricing remains pending its pilot. These are reference prices, not receipts.

The `own`, `gift` and `code` query parameters and local browser preferences are
untrusted presentation input. They never prove ownership, authorize credit or
activate checkout. Gifts and upgrades are explicitly blocked; there is no public
USD 40 Max checkout. A syntactically valid legacy code cannot bypass that block.

`src/lib/pricing.ts` computes preview states; `src/lib/checkout.ts` enforces the
inactive provider boundary. Any future activation requires accepted server-side
identity, price, entitlement/refund and delivery integration plus separate
release authorization. Private commerce implementation and credentials stay
outside this public repository and the offline Python runtime.


## Cloudflare static website and separate account

The website stays static and public. Build with `SITE_URL` set to the intended
HTTPS domain root for Cloudflare. `wrangler.static.jsonc` serves only `dist/`;
no account API, paid ZIP or private service source belongs in this project.

Set `PUBLIC_ACCOUNT_URL=https://account.example.test/account` to show an account
navigation link. This is a build-time HTTPS destination, not authentication or
checkout activation. Empty means hidden. Credentials, query/fragment and paths
other than `/account` are rejected; a bare origin is normalized to `/account`.
The account service owns its API on its own origin. Do not proxy bearer tokens
through this static site. The example domain is synthetic, not a deployment.

Local QA uses `SESSLINT_WEB_OFFLINE=1`; run check, test, build, docs, links and
Chromium E2E sequentially. Test both an unset account URL and an explicitly
configured synthetic URL. Payment buttons remain closed in both builds.
