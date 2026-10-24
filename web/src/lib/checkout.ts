// Checkout seam. Payments are not live until PUBLIC_CHECKOUT_<SKU> (e.g.
// PUBLIC_CHECKOUT_MAX, PUBLIC_CHECKOUT_GIFT_PLUS) is set to the provider's
// hosted checkout URL at build time; until then /checkout shows the order
// summary with a "payments open soon" state. No UI changes are needed.
//
// Upgrades have no checkout link of their own. A public "$40 Max" link would
// sell Max at the upgrade price to anyone, so an upgrade is the target tier's
// normal checkout with the buyer's single-use upgrade code applied. The
// provider, not this static site, enforces the credit: the code exists only
// in the Plus buyer's receipt email (see web/README.md, "Upgrade codes").

import type { Quote } from "./pricing";

export const SKUS = ["plus", "max", "gift_plus", "gift_max"] as const;
export type Sku = (typeof SKUS)[number];

export type CheckoutLinks = Partial<Record<Sku, string>>;

export type CheckoutConfig = {
  links: CheckoutLinks;
  /** Query parameter that pre-fills a discount code on the provider's page. */
  codeParam: string;
};

/** Lemon Squeezy's prefill parameter; Stripe Payment Links use `prefilled_promo_code`. */
export const DEFAULT_CODE_PARAM = "checkout[discount_code]";

/**
 * Upgrade code: "SLUP" + 12 Crockford base32 characters (60 random bits),
 * minted per Plus order by the purchase webhook. Readers may type it with
 * spaces, hyphens or lower case.
 */
export const UPGRADE_CODE = /^SLUP[0-9A-HJKMNP-TV-Z]{12}$/;

export function normalizeCode(raw: string): string {
  return raw.toUpperCase().replace(/[\s-]+/g, "");
}

/** Group a normalized code for display: SLUP 7K2Q M9XH 4TRA. */
export function formatCode(code: string): string {
  return code.replace(/(.{4})(?=.)/g, "$1 ");
}

function https(url: string | undefined): string | undefined {
  return url && /^https:\/\//.test(url) ? url : undefined;
}

/** Read hosted checkout URLs and the code parameter at build time. */
export function checkoutConfig(env: Record<string, string | undefined>): CheckoutConfig {
  const links: CheckoutLinks = {};
  for (const sku of SKUS) {
    const url = https(env[`PUBLIC_CHECKOUT_${sku.toUpperCase()}`]);
    if (url) links[sku] = url;
  }
  const param = env.PUBLIC_CHECKOUT_CODE_PARAM?.trim();
  return { links, codeParam: param || DEFAULT_CODE_PARAM };
}

export function isLive(cfg: CheckoutConfig): boolean {
  return Object.keys(cfg.links).length > 0;
}

export type Resolution =
  | { kind: "ready"; url: string }
  | { kind: "blocked" } // the quote itself refuses (already owned, free, …)
  | { kind: "need-code" } // upgrade without a code yet
  | { kind: "bad-code" } // something typed that is not an upgrade code
  | { kind: "not-live" }; // no checkout link configured for this SKU

export function isUpgrade(q: Quote): boolean {
  return q.allowed && !q.gift && q.creditCents > 0;
}

/** Where "Continue to secure checkout" goes for this quote, if anywhere. */
export function resolveCheckout(q: Quote, cfg: CheckoutConfig, rawCode: string | null = null): Resolution {
  if (!q.allowed || !q.sku) return { kind: "blocked" };
  if (!isUpgrade(q)) {
    const url = cfg.links[q.sku as Sku];
    return url ? { kind: "ready", url } : { kind: "not-live" };
  }
  const code = normalizeCode(rawCode ?? "");
  if (!code) return { kind: "need-code" };
  if (!UPGRADE_CODE.test(code)) return { kind: "bad-code" };
  const link = cfg.links[q.target as Sku];
  if (!link) return { kind: "not-live" };
  const url = new URL(link);
  url.searchParams.set(cfg.codeParam, code);
  return { kind: "ready", url: url.toString() };
}
