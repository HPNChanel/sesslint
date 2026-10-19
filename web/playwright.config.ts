import { defineConfig, devices } from "@playwright/test";
import { siteLocation } from "./site.config.mjs";

// e2e runs against the built site (`npm run build` first), served the way
// GitHub Pages serves it: under the SITE_URL path, 404.html with a real 404.
const PORT = 4322;
const ROOT = `http://localhost:${PORT}${siteLocation().prefix}/`;

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: ROOT,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `node scripts/serve.mjs ${PORT}`,
    url: ROOT,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
