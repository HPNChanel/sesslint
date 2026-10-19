import { describe, expect, it } from "vitest";
import { quote, usd } from "../../src/lib/pricing";

describe("quote", () => {
  it("charges list price for a first purchase", () => {
    expect(quote("plus").dueCents).toBe(900);
    expect(quote("max").dueCents).toBe(4900);
    expect(quote("max").sku).toBe("max");
  });

  it("credits the owned tier on upgrade", () => {
    const q = quote("max", "plus");
    expect(q.allowed).toBe(true);
    expect(q.creditCents).toBe(900);
    expect(q.dueCents).toBe(4000);
    expect(q.sku).toBe("upgrade_plus_max");
    expect(q.lines.map((l) => l.cents)).toEqual([4900, -900]);
  });

  it("refuses same-tier and downgrade purchases", () => {
    expect(quote("plus", "plus")).toMatchObject({ allowed: false, reason: "already-owned" });
    expect(quote("plus", "max")).toMatchObject({ allowed: false, reason: "already-owned" });
    expect(quote("max", "max")).toMatchObject({ allowed: false, reason: "already-owned" });
  });

  it("never credits gifts and allows gifting while owning a tier", () => {
    const g = quote("plus", "max", true);
    expect(g).toMatchObject({ allowed: true, dueCents: 900, creditCents: 0, sku: "gift_plus" });
    expect(quote("max", "plus", true).dueCents).toBe(4900);
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
