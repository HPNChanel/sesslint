import { expect, test } from "./fixtures";

test("command palette opens with Ctrl+K and jumps to an SL code", async ({ page }) => {
  await page.goto("");
  await page.keyboard.press("Control+k");
  const input = page.getByRole("combobox");
  await expect(input).toBeFocused();
  await input.fill("SL203");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/rules\/?#SL203$/);
});

test("palette closes on Escape and returns focus", async ({ page }) => {
  await page.goto("pricing/");
  await page.keyboard.press("Control+k");
  await expect(page.locator("[data-palette]")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("[data-palette]")).toBeHidden();
});

test("pipeline tabs follow the ARIA keyboard pattern", async ({ page }) => {
  await page.goto("");
  const check = page.getByRole("tab", { name: "check", exact: true }).last();
  await check.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "triage" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("#pp-triage")).toBeVisible();
  await expect(page.locator("#pp-check")).toBeHidden();
});

test("rules filter narrows the catalog", async ({ page }) => {
  await page.goto("rules/");
  const total = await page.locator("[data-rule]").count();
  expect(total).toBeGreaterThan(30);
  await page.locator("[data-rule-search]").fill("SL203");
  await expect(page.locator("[data-rule]:visible")).toHaveCount(1);
  await expect(page.locator("[data-rule-count]")).toHaveText(`1/${total}`);
});

test("changelog filter shows only breaking entries", async ({ page }) => {
  await page.goto("changelog/");
  await page.locator("input[data-cl-filter][value=breaking]").check();
  const visible = page.locator("[data-entry]:visible");
  expect(await visible.count()).toBeGreaterThan(0);
  for (const flag of await visible.evaluateAll((els) => els.map((e) => e.getAttribute("data-breaking")))) {
    expect(flag).toBe("true");
  }
});

test("replay reaches the verified state, and reduced motion shows it immediately", async ({ page, browser }) => {
  await page.goto("");
  await page.locator("sl-replay [data-goto='2']").click();
  await expect(page.locator("sl-replay")).toHaveAttribute("data-state", "verify");
  await expect(page.locator("sl-replay").getByText("Verification: PASSED")).toBeVisible();

  const ctx = await browser.newContext({ reducedMotion: "reduce" });
  const still = await ctx.newPage();
  await still.route("https://api.github.com/**", (r) => r.fulfill({ json: {} }));
  await still.goto("/sesslint/");
  await expect(still.locator("sl-replay")).toHaveAttribute("data-state", "verify");
  await expect(still.locator("sl-replay [data-play]")).toBeHidden();
  await ctx.close();
});

test.describe("live release ribbon", () => {
  test.use({ latestTag: "v99.0.0" });
  test("appears when GitHub has a newer release than the build", async ({ page }) => {
    await page.goto("changelog/");
    const ribbon = page.locator("sl-live-release");
    await expect(ribbon).toBeVisible();
    await expect(ribbon).toContainText("v99.0.0");
    await ribbon.getByRole("button").click();
    await expect(ribbon).toBeHidden();
  });
});

test("live release ribbon stays hidden when the build is current", async ({ page }) => {
  await page.goto("changelog/");
  await page.waitForLoadState("networkidle");
  await expect(page.locator("sl-live-release")).toBeHidden();
});
