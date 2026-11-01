import { describe, expect, it } from "vitest";
import {
  DEFAULT_CODE_PARAM,
  checkoutConfig,
  formatCode,
  isLive,
  normalizeCode,
  publicConfig,
  resolveCheckout,
  UPGRADE_CODE,
} from "../../src/lib/checkout";
import { quote } from "../../src/lib/pricing";

const CODE = "SLUP7K2QM9XH4TRA";
const live = checkoutConfig({
  PUBLIC_CHECKOUT_PLUS: "https://pay.example/plus",
  PUBLIC_CHECKOUT_MAX: "https://pay.example/max?ref=site",
  PUBLIC_CHECKOUT_GIFT_MAX: "https://pay.example/gift-max",
});

describe("checkoutConfig", () => {
  it("is not live with no links, and ignores non-https URLs", () => {
    expect(isLive(checkoutConfig({}))).toBe(false);
    expect(checkoutConfig({ PUBLIC_CHECKOUT_MAX: "http://pay.example/max" }).links).toEqual({});
  });

  it("never reads a standalone upgrade link", () => {
    const cfg = checkoutConfig({ PUBLIC_CHECKOUT_UPGRADE_PLUS_MAX: "https://pay.example/cheap-max" });
    expect(cfg.links).toEqual({});
  });

  it("defaults the code parameter and accepts an override", () => {
    expect(live.codeParam).toBe(DEFAULT_CODE_PARAM);
    expect(checkoutConfig({ PUBLIC_CHECKOUT_CODE_PARAM: "prefilled_promo_code" }).codeParam).toBe(
      "prefilled_promo_code",
    );
  });
});

describe("upgrade codes", () => {
  it("normalizes spacing, hyphens and case", () => {
    expect(normalizeCode(" slup-7k2q m9xh-4tra ")).toBe(CODE);
    expect(formatCode(CODE)).toBe("SLUP 7K2Q M9XH 4TRA");
    expect(UPGRADE_CODE.test(CODE)).toBe(true);
  });

  it("rejects wrong prefix, length and ambiguous letters", () => {
    for (const bad of ["SLUP7K2QM9XH4TR", "XLUP7K2QM9XH4TRA", "SLUP7K2QM9XH4TRI", "SLUPOOOOOOOOOOOO"]) {
      expect(UPGRADE_CODE.test(bad)).toBe(false);
    }
  });
});

describe("resolveCheckout", () => {
  it("keeps every payment path inert and blocks direct gift quotes", () => {
    expect(resolveCheckout(quote("max"), live)).toEqual({ kind: "not-live" });
    expect(resolveCheckout(quote("max", "plus", true), live)).toEqual({ kind: "blocked" });
  });

  it("never treats a formatted code as proof of a Plus purchase", () => {
    const up = quote("max", "plus");
    expect(resolveCheckout(up, live, CODE)).toEqual({ kind: "blocked" });
  });

  it("refused quotes never resolve, even with a code", () => {
    expect(resolveCheckout(quote("plus", "max"), live, CODE)).toEqual({ kind: "blocked" });
    expect(resolveCheckout(quote("free"), live)).toEqual({ kind: "blocked" });
  });

  it("keeps a supplied checkout URL inert until integration acceptance", () => {
    expect(isLive(live)).toBe(false);
  });
});

describe("publicConfig", () => {
  it("serializes no provider URL while checkout is closed", () => {
    expect(isLive(live)).toBe(false);
    const shipped = publicConfig(live);
    expect(shipped.links).toEqual({});
    expect(JSON.stringify(shipped)).not.toContain("pay.example");
    expect(shipped.codeParam).toBe(DEFAULT_CODE_PARAM);
  });
});
