import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.PARSER_STUDIO_TEST_PORT || 5180);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid isolated browser test port');

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  outputDir: process.env.PARSER_STUDIO_TEST_OUTPUT_DIR || 'test-results',
  retries: 0,
  workers: 2,
  reporter: 'list',
  timeout: 30_000,
  use: {
    baseURL: 'http://127.0.0.1:' + port,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1440, height: 900 },
  },
  projects: [{
    name: 'chromium',
    use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
  }],
  webServer: {
    command: 'npm run dev -- --port ' + port + ' --strictPort',
    url: 'http://127.0.0.1:' + port + '/',
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
