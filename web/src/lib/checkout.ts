// Checkout seam. Payments are not live yet: every SKU resolves to null and
// the /checkout page shows the order summary with a "payments open soon"
// state. To go live, set PUBLIC_CHECKOUT_<SKU> (e.g. PUBLIC_CHECKOUT_MAX,
// PUBLIC_CHECKOUT_UPGRADE_PLUS_MAX, PUBLIC_CHECKOUT_GIFT_PLUS) to the
// provider's hosted checkout URL at build time; no UI changes are needed.

export const SKUS = ["plus", "max", "upgrade_plus_max", "gift_plus", "gift_max"] as const;
export type Sku = (typeof SKUS)[number];

export type CheckoutLinks = Partial<Record<Sku, string>>;

/** Read hosted checkout URLs from PUBLIC_CHECKOUT_* at build time. */
export function checkoutLinks(env: Record<string, string | undefined>): CheckoutLinks {
  const out: CheckoutLinks = {};
  for (const sku of SKUS) {
    const url = env[`PUBLIC_CHECKOUT_${sku.toUpperCase()}`];
    if (url && /^https:\/\//.test(url)) out[sku] = url;
  }
  return out;
}

export function isLive(links: CheckoutLinks): boolean {
  return Object.keys(links).length > 0;
}
