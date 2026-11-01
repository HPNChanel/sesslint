import { expect, test } from "./fixtures";

const receipt = (page: import("@playwright/test").Page, tier: string) => page.locator(`[data-receipt=${tier}]`);

// Approved launch boundary: query parameters never activate gifts, credit or payment.
test("first purchase shows list prices", async ({ page }) => {
  await page.goto("pricing/");
  await expect(receipt(page, "plus").locator("[data-r-due]")).toHaveText("$9.00");
  await expect(receipt(page, "max").locator("[data-r-due]")).toHaveText("$49.00");
});

for (const locale of ["", "vi/"]) {
  test(`${locale || "en/"} ownership selector cannot grant upgrade credit`, async ({ page }) => {
    await page.goto(`${locale}pricing/`);
    await page.getByRole("radio", { name: "Plus" }).check();
    await expect(page).toHaveURL(/own=plus/);
    const max = receipt(page, "max");
    await expect(max.locator("[data-r-credit]")).toBeHidden();
    await expect(max.locator("[data-r-credit-amt]")).toHaveText("$0.00");
    await expect(max.locator("[data-r-big]")).toHaveText("$49");
    await expect(max.locator("[data-r-cta]")).toHaveText(locale ? "Chưa hỗ trợ nâng cấp" : "Upgrade unavailable");
    for (const tier of ["plus", "max"]) {
      await expect(receipt(page, tier).locator("[data-r-cta]")).toHaveAttribute("aria-disabled", "true");
      await expect(receipt(page, tier).locator("[data-r-cta]")).not.toHaveAttribute("href", /.+/);
    }
  });
}

test("gift query cannot restore a gift control or a gift purchase link", async ({ page }) => {
  await page.goto("pricing/?own=plus&gift=1");
  await expect(page.getByRole("switch")).toHaveCount(0);
  await expect(page).not.toHaveURL(/gift=1/);
  await expect(receipt(page, "max").locator("[data-r-credit]")).toBeHidden();
  await expect(receipt(page, "max").locator("[data-r-cta]")).not.toHaveAttribute("href", /.+/);
});

test("deep link restores presentation state without offering repurchase", async ({ page }) => {
  await page.goto("pricing/?own=max");
  await expect(page.getByRole("radio", { name: "Max" })).toBeChecked();
  await expect(receipt(page, "max").locator("[data-r-due]")).toHaveText("$0.00");
  await expect(receipt(page, "max").locator("[data-r-cta]")).toHaveAttribute("aria-disabled", "true");
  await expect(receipt(page, "max").locator("[data-r-cta]")).not.toHaveAttribute("href", /.+/);
});

test("checkout refuses unverified upgrade, gift and repurchase", async ({ page }) => {
  for (const query of ["tier=max&own=plus", "tier=plus&own=max", "tier=max&gift=1"]) {
    await page.goto(`checkout/?${query}`);
    await expect(page.locator("[data-o-invalid]")).toBeVisible();
    await expect(page.locator("[data-o-reason]")).not.toHaveText("");
    await expect(page.locator("[data-o-due]")).toHaveText("$0.00");
    await expect(page.locator("[data-o-credit]")).toBeHidden();
    await expect(page.getByRole("button", { name: /secure checkout/ })).toBeDisabled();
    await expect(page.locator("a[data-o-proceed]")).toHaveCount(0);
  }
});

test("well-formed legacy codes cannot bypass the inactive integration", async ({ page }) => {
  for (const code of ["hello", "SLUP7K2QM9XH4TRA"]) {
    await page.goto(`checkout/?tier=max&own=plus&code=${code}`);
    await expect(page.locator("[data-o-code]")).toBeHidden();
    await expect(page.locator("[data-o-reason]")).toContainText("provider-side purchase proof");
    await expect(page.locator("a[data-o-proceed]")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /secure checkout/ })).toBeDisabled();
  }
});

test("new purchase preview has correct price but cannot navigate to a provider", async ({ page }) => {
  await page.goto("checkout/?tier=max");
  await expect(page.locator("[data-o-due]")).toHaveText("$49.00");
  await expect(page.locator("[data-o-invalid]")).toBeHidden();
  await expect(page.locator("[data-o-code]")).toBeHidden();
  await expect(page.locator("#not-live")).toBeVisible();
  await expect(page.getByRole("button", { name: /secure checkout/ })).toBeDisabled();
  await expect(page.locator("a[data-o-proceed]")).toHaveCount(0);
});

test("pricing rejects code-based upgrade links rather than forwarding the code", async ({ page }) => {
  await page.goto("pricing/?own=plus&code=SLUP7K2QM9XH4TRA");
  for (const tier of ["plus", "max"]) {
    await expect(receipt(page, tier).locator("[data-r-cta]")).not.toHaveAttribute("href", /.+/);
  }
});
