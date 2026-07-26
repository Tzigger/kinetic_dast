import { defineConfig, devices } from '@playwright/test';

/**
 * Isolated Playwright configuration for the Juice Shop regression suite.
 *
 * This deliberately does not reuse the repository's default Playwright
 * configuration: that configuration logs into bWAPP during global setup and
 * loads its authenticated storage state. Juice Shop tests need an independent,
 * anonymous browser context for every test.
 */
export default defineConfig({
  testDir: './tests/juice-shop',
  testMatch: '**/*.spec.ts',

  // Security scans can alter application state, so keep the target isolated
  // while still allowing Playwright's normal per-test browser contexts.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 2 : 0,
  timeout: 180_000,
  expect: {
    timeout: 10_000,
  },
  outputDir: 'test-results/juice-shop',
  reporter: process.env['CI'] ? [['github'], ['line']] : 'line',

  use: {
    baseURL: process.env['JUICE_SHOP_URL'] ?? 'http://localhost:3000',
    // No storageState: every test starts as an unauthenticated Juice Shop user.
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
