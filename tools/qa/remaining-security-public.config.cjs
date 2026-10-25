'use strict';
const {defineConfig,devices}=require('@playwright/test');
// Explicit operator-only live browser QA. No public network in default CI.
module.exports=defineConfig({
 testDir:'../../tests',
 testMatch:'**/remaining-security-*-20261026.spec.ts',
 retries:0,workers:1,timeout:60000,
 reporter:'list',
 outputDir:process.env.PARSER_STUDIO_PUBLIC_QA_OUTPUT_DIR||
  '../../test-results/remaining-security-public',
 use:{baseURL:'https://app.parser.xdr.ooo',viewport:{width:1440,height:900},
  trace:'retain-on-failure',screenshot:'only-on-failure',acceptDownloads:true},
 projects:[{name:'chromium',use:{...devices['Desktop Chrome'],viewport:{width:1440,height:900}}}]
});
