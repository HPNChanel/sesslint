import { describe, expect, it } from "vitest";
import { accountUrl } from "../../src/lib/account";

describe("separate account navigation", () => {
  it("has no target until explicitly configured", () => {
    expect(accountUrl(undefined)).toBeNull(); expect(accountUrl("  ")).toBeNull();
  });
  it("normalizes the HTTPS account origin or account page", () => {
    for (const value of ["https://account.example.test", "https://account.example.test/account/", " https://account.example.test/account "]) {
      expect(accountUrl(value)).toBe("https://account.example.test/account");
    }
  });
  it("refuses active URLs, credentials, unexpected paths and token-bearing URLs", () => {
    for (const value of ["http://localhost:3000/account", "javascript:alert(1)", "/account", "https://u:p@example.test/account", "https://example.test/checkout", "https://example.test/account?token=secret", "https://example.test/account#secret"]) {
      expect(() => accountUrl(value)).toThrow(/PUBLIC_ACCOUNT_URL/);
    }
  });
});
