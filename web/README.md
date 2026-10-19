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

Payments are off until hosted checkout links are configured. With no links,
`/checkout` shows the order and a "payments open soon" notice, and its button
stays disabled. Set these repository variables (they are public URLs, not
secrets) and re-run the workflow:

| Variable | Checkout |
| --- | --- |
| `PUBLIC_CHECKOUT_PLUS` | Plus, $9 |
| `PUBLIC_CHECKOUT_MAX` | Max, $49; also the upgrade target |
| `PUBLIC_CHECKOUT_GIFT_PLUS` | Plus bought as a gift, $9 |
| `PUBLIC_CHECKOUT_GIFT_MAX` | Max bought as a gift, $49 |
| `PUBLIC_CHECKOUT_CODE_PARAM` | Query parameter that pre-fills a discount code. Default `checkout[discount_code]` (Lemon Squeezy). Stripe Payment Links: `prefilled_promo_code`. |

Only `https://` links are accepted. Pricing logic lives in `src/lib/pricing.ts`,
link resolution in `src/lib/checkout.ts`; both are pure and unit-tested.

### Upgrade codes (Plus → Max for $40)

The site is static and has no accounts, so it cannot know who owns Plus. The
proof is a **single-use upgrade code** that only a Plus buyer receives. There
is deliberately no standalone "$40 Max" link: anyone could use it.

Flow:

1. A customer buys Plus.
2. The provider's `order_created` webhook (or equivalent) mints a code and
   stores it as a discount on the provider:
   - format `SLUP` + 12 Crockford base32 characters (`0-9 A-H J K M N P-T V-Z`),
     60 random bits from a CSPRNG, e.g. `SLUP7K2QM9XH4TRA`;
   - amount: a fixed $9.00 off (the Plus price);
   - applies to the Max product only;
   - one redemption in total, no expiry (the purchase is for life);
   - linked to the Plus order, so it is revoked if that order is refunded.
3. The Plus receipt email carries the code and the upgrade link:
   `${SITE_URL}/checkout/?tier=max&own=plus&code=SLUP7K2QM9XH4TRA`
   (Vietnamese: `${SITE_URL}/vi/checkout/?tier=max&own=plus&code=…`).
4. The checkout page pre-fills the code, checks its format, and sends the buyer
   to `PUBLIC_CHECKOUT_MAX` with the code in `PUBLIC_CHECKOUT_CODE_PARAM`.
   Buyers who arrive via "I already own: Plus" on /pricing paste the code.
5. The provider validates and redeems the code, charging $49 − $9 = $40. The
   site never decides the price; a guessed or reused code is refused there.
6. On the Max order, issue the Max license. The Plus license may stay active:
   it is the same customer.

A shared code transfers at most the $9 the buyer already paid, once, which
is the same as gifting it. Support resends lost codes by replying to the Plus
receipt; the site asks for no email.
