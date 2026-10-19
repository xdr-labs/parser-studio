import {defineConfig,devices} from '@playwright/test';
export default defineConfig({
 testDir:'tests',testMatch:'novice-corpus-*-public-20261019.spec.ts',
 outputDir:'/tmp/parser-poc-public-full-corpus-results-20261019',
 reporter:'list',retries:0,workers:4,timeout:35000,
 use:{baseURL:'https://app.parser.xdr.ooo/',trace:'retain-on-failure',screenshot:'only-on-failure',viewport:{width:1440,height:900}},
 projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}]
});
