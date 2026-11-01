// Reference prices for the static preview, never authoritative purchase proof.
// Gift and upgrade checkout remain blocked pending accepted provider integration.
// Same/lower tier is not purchasable; Free is never sold or gifted.
import { TIERS, type TierId } from "../data/tiers";

export type Line = { kind: "item" | "credit"; tier: TierId; cents: number };

export type Quote = {
  target: TierId;
  owned: TierId;
  gift: boolean;
  listCents: number;
  creditCents: number;
  dueCents: number;
  lines: Line[];
  allowed: boolean;
  reason: "ok" | "free" | "already-owned" | "not-giftable" | "gift-disabled" | "proof-required";
  /**
   * Checkout SKU, e.g. "max", "upgrade_plus_max", "gift_plus". Upgrade SKUs
   * have no link of their own: checkout.ts sends them to the target tier's
   * checkout with the buyer's single-use upgrade code.
   */
  sku: string | null;
};

export function isTierId(v: unknown): v is TierId {
  return v === "free" || v === "plus" || v === "max";
}

export function quote(target: TierId, owned: TierId = "free", gift = false): Quote {
  const t = TIERS[target];
  const o = TIERS[owned];
  const base: Quote = {
    target,
    owned,
    gift,
    listCents: t.priceCents,
    creditCents: 0,
    dueCents: t.priceCents,
    lines: [{ kind: "item", tier: target, cents: t.priceCents }],
    allowed: true,
    reason: "ok",
    sku: null,
  };

  if (t.priceCents === 0) return { ...base, allowed: false, reason: "free", dueCents: 0 };

  if (gift) {
    return { ...base, allowed: false, reason: "gift-disabled", dueCents: 0 };
  }

  if (t.rank <= o.rank) {
    return { ...base, allowed: false, reason: "already-owned", dueCents: 0 };
  }

  if (o.priceCents > 0) {
    // A static query parameter is not purchase proof. Credit stays unavailable
    // until a provider-side entitlement check is integrated.
    return { ...base, allowed: false, reason: "proof-required", dueCents: 0 };
  }

  return { ...base, sku: target };
}

const USD = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
});

/** USD is the reference currency in every locale. */
export function usd(cents: number): string {
  const s = USD.format(Math.abs(cents) / 100);
  return cents < 0 ? `−${s}` : s;
}

/** Whole-dollar label for headline prices ($9, $49). */
export function usdShort(cents: number): string {
  return cents % 100 === 0 ? `$${cents / 100}` : usd(cents);
}
