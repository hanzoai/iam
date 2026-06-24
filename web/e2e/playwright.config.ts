// Playwright config for the wallet-login e2e. Boots the Vite harness dev server
// (e2e/vite.e2e.config.ts) which proxies /v1/iam to the IAM backend on :8000.
// The IAM backend itself must already be running (see e2e/run.sh) — Playwright
// only owns the frontend; the real server is the system under test.
import {defineConfig, devices} from "@playwright/test";
import {fileURLToPath} from "node:url";
import {dirname, resolve} from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  testDir: here,
  testMatch: "**/*.spec.ts",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:7100",
    headless: true,
    trace: "retain-on-failure",
    viewport: {width: 1280, height: 900},
  },
  projects: [{name: "chromium", use: {...devices["Desktop Chrome"]}}],
  webServer: {
    command: "vite --config vite.e2e.config.ts",
    cwd: here,
    url: "http://localhost:7100/harness.html",
    timeout: 120_000,
    reuseExistingServer: true,
    stdout: "pipe",
    stderr: "pipe",
  },
});
