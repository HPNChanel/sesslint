// One-time purchase pricing. Pure and browser-safe: the same function
// renders the static receipts at build time and recomputes them live when a
// visitor toggles "I already own" or "This is a gift".
//
// Rules:
//   - upgrade (not a gift, target ranks above owned): pay the difference;
//   - same or lower tier for yourself: not purchasable (already owned);
//   - gift: always full price, never credited, any paid tier;
//   - Free is never sold or gifted.
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
  reason: "ok" | "free" | "already-owned" | "not-giftable";
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
    if (!t.giftable) return { ...base, allowed: false, reason: "not-giftable" };
    return { ...base, sku: `gift_${target}` };
  }

  if (t.rank <= o.rank) {
    return { ...base, allowed: false, reason: "already-owned", dueCents: 0 };
  }

  if (o.priceCents > 0) {
    const credit = Math.min(o.priceCents, t.priceCents);
    return {
      ...base,
      creditCents: credit,
      dueCents: t.priceCents - credit,
      lines: [...base.lines, { kind: "credit", tier: owned, cents: -credit }],
      sku: `upgrade_${owned}_${target}`,
    };
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
