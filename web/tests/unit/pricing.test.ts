import { describe, expect, it } from "vitest";
import { quote, usd } from "../../src/lib/pricing";

describe("quote", () => {
  it("charges list price for a first purchase", () => {
    expect(quote("plus").dueCents).toBe(900);
    expect(quote("max").dueCents).toBe(4900);
    expect(quote("max").sku).toBe("max");
  });

  it("refuses an upgrade until provider-side purchase proof exists", () => {
    const q = quote("max", "plus");
    expect(q).toMatchObject({ allowed: false, reason: "proof-required", creditCents: 0, dueCents: 0 });
  });

  it("refuses same-tier and downgrade purchases", () => {
    expect(quote("plus", "plus")).toMatchObject({ allowed: false, reason: "already-owned" });
    expect(quote("plus", "max")).toMatchObject({ allowed: false, reason: "already-owned" });
    expect(quote("max", "max")).toMatchObject({ allowed: false, reason: "already-owned" });
  });

  it("blocks gifts even when a direct query tries to request one", () => {
    const g = quote("plus", "max", true);
    expect(g).toMatchObject({ allowed: false, reason: "gift-disabled", dueCents: 0, sku: null });
    expect(quote("max", "plus", true)).toMatchObject({ allowed: false, reason: "gift-disabled" });
  });

  it("never sells or gifts Free", () => {
    expect(quote("free")).toMatchObject({ allowed: false, reason: "free", dueCents: 0 });
    expect(quote("free", "free", true)).toMatchObject({ allowed: false });
  });

  it("formats USD in every locale", () => {
    expect(usd(4000)).toBe("$40.00");
    expect(usd(-900)).toBe("−$9.00");
  });
});
