import {defineConfig,devices} from '@playwright/test';
export default defineConfig({
  testDir:'tests',
  testMatch:['rfc5424-msg-real-browser-20261019.isolated.ts','rfc3164-content-real-browser-20261020.isolated.ts'],
  outputDir:'/tmp/parser-rfc5424-msg-chromium-artifacts-20261019',
  reporter:'list',
  workers:1,
  retries:0,
  timeout:45000,
  use:{
    baseURL:'http://127.0.0.1:5180/',
    trace:'retain-on-failure',
    screenshot:'only-on-failure',
    viewport:{width:1440,height:900},
  },
  projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}],
});
