import { ALL, expect, test } from "./fixtures";

for (const path of ALL) {
  test(`renders /${path} without errors`, async ({ page, errors }) => {
    const res = await page.goto(path);
    expect(res?.ok()).toBe(true);
    await expect(page.locator("h1").first()).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("lang", path.startsWith("vi/") ? "vi" : "en");
    expect(errors).toEqual([]);
  });
}

for (const width of [375, 1366]) {
  test(`no horizontal scroll at ${width}px`, async ({ page, errors }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ALL) {
      await page.goto(path);
      if (path.endsWith("download/")) await page.locator("#tab-binary").click();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow, `/${path}`).toBeLessThanOrEqual(0);
    }
    expect(errors).toEqual([]);
  });
}

test("unknown route shows the CLI-style 404 with suggestions", async ({ page }) => {
  const res = await page.goto("pricng/");
  expect(res?.status()).toBe(404);
  await expect(page.locator("h1")).toContainText("route not found");
  await expect(page.locator("[data-nf-sugg] a").first()).toHaveText("/pricing");
});

test("theme toggle persists across navigation", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("");
  const theme = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const before = await theme();
  await page.locator("[data-theme-toggle]").first().click();
  const after = await theme();
  expect(after).not.toBe(before);
  await page.goto("pricing/");
  expect(await theme()).toBe(after);
});

test("language switch keeps the current page", async ({ page }) => {
  await page.goto("pricing/");
  await page.locator("a[hreflang=vi]").first().click();
  await expect(page).toHaveURL(/\/vi\/pricing\/?$/);
  await expect(page.locator("html")).toHaveAttribute("lang", "vi");
});
