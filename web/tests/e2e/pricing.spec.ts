import { expect, test } from "./fixtures";

const receipt = (page: import("@playwright/test").Page, tier: string) => page.locator(`[data-receipt=${tier}]`);

test("first purchase shows list prices", async ({ page }) => {
  await page.goto("pricing/");
  await expect(receipt(page, "plus").locator("[data-r-due]")).toHaveText("$9.00");
  await expect(receipt(page, "max").locator("[data-r-due]")).toHaveText("$49.00");
});

test("owning Plus credits $9 toward Max and blocks Plus", async ({ page }) => {
  await page.goto("pricing/");
  await page.getByRole("radio", { name: "Plus" }).check();
  await expect(page).toHaveURL(/own=plus/);
  const max = receipt(page, "max");
  await expect(max.locator("[data-r-credit-amt]")).toHaveText("−$9.00");
  await expect(max.locator("[data-r-due]")).toHaveText("$40.00");
  await expect(max.locator("[data-r-cta]")).toHaveAttribute("href", /checkout\?tier=max&own=plus/);
  await expect(receipt(page, "plus").locator("[data-r-cta]")).not.toHaveAttribute("href", /.+/);
});

test("gifts are full price and never use credit", async ({ page }) => {
  await page.goto("pricing/?own=plus");
  await page.getByRole("switch", { name: /gift/ }).check();
  await expect(page).toHaveURL(/gift=1/);
  const max = receipt(page, "max");
  await expect(max.locator("[data-r-due]")).toHaveText("$49.00");
  await expect(max.locator("[data-r-credit]")).toBeHidden();
  await expect(max.locator("[data-r-who]")).toHaveText("recipient");
});

test("deep link restores state", async ({ page }) => {
  await page.goto("pricing/?own=max");
  await expect(page.getByRole("radio", { name: "Max" })).toBeChecked();
  await expect(receipt(page, "max").locator("[data-r-due]")).toHaveText("$0.00");
});

test("checkout prices the upgrade and refuses re-buying", async ({ page }) => {
  await page.goto("checkout/?tier=max&own=plus");
  await expect(page.locator("[data-o-due]")).toHaveText("$40.00");
  await expect(page.locator("[data-o-invalid]")).toBeHidden();
  await expect(page.getByRole("button", { name: /secure checkout/ })).toBeDisabled();

  await page.goto("checkout/?tier=plus&own=max");
  await expect(page.locator("[data-o-invalid]")).toBeVisible();
  await expect(page.locator("[data-o-due]")).toHaveText("$0.00");
});
