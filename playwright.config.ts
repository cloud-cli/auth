import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/integration',
  timeout: 30_000,
  use: {
    baseURL: process.env.INTEGRATION_BASE_URL || 'http://127.0.0.1:3000',
    trace: 'retain-on-failure',
  },
  webServer: process.env.INTEGRATION_BASE_URL ? undefined : {
    command: 'pnpm start',
    url: 'http://127.0.0.1:3000/',
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
