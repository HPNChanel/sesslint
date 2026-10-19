import { defineConfig, devices } from "@playwright/test";

// e2e runs against the built site (`npm run build` first), served the way
// GitHub Pages serves it: /sesslint base, 404.html with a real 404 status.
const PORT = 4322;

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://localhost:${PORT}/sesslint/`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `node scripts/serve.mjs ${PORT}`,
    url: `http://localhost:${PORT}/sesslint/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
