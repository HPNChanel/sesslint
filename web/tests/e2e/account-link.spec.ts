import { expect, test } from "./fixtures";
import { accountUrl } from "../../src/lib/account";

for (const lang of ["en", "vi"] as const) {
  test(`account link is explicit navigation, never checkout activation (${lang})`, async ({ page }) => {
    await page.goto(lang === "vi" ? "vi/" : "");
    const links = page.locator("a[data-account-link]");
    const target = accountUrl(process.env.PUBLIC_ACCOUNT_URL);
    if (!target) { await expect(links).toHaveCount(0); return; }
    await expect(links).toHaveCount(3);
    for (const link of await links.all()) await expect(link).toHaveAttribute("href", target);
    // Browser navigation is intercepted locally; this does not contact an account service.
    await page.route(`${target}**`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<h1>Synthetic account destination</h1>" }));
    await links.first().click();
    await expect(page.getByRole("heading", { name: "Synthetic account destination" })).toBeVisible();
    expect(page.url()).toBe(target);
  });
}
