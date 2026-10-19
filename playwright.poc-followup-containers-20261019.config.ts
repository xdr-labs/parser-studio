import {defineConfig,devices} from '@playwright/test';
const uiPort=5501,enginePort=5502;
export default defineConfig({
 testDir:'tests',
 testMatch:['novice-audit-cri-docker-20261019.spec.ts'],
 outputDir:'/tmp/parser-poc-followup-container-browser-artifacts-20261019',
 reporter:'list',workers:1,retries:0,timeout:35000,
 use:{baseURL:'http://127.0.0.1:'+uiPort,viewport:{width:1440,height:900},trace:'retain-on-failure',screenshot:'only-on-failure'},
 projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}],
 webServer:[
  {command:'python3 runtime/multipass/multipass_preview_api.py --port '+enginePort,
   url:'http://127.0.0.1:'+enginePort+'/health',timeout:30000,reuseExistingServer:false},
  {command:'npm run dev -- --port '+uiPort+' --strictPort',
   url:'http://127.0.0.1:'+uiPort+'/',
   env:{PARSER_STUDIO_MULTIPASS_PORT:String(enginePort),PARSER_STUDIO_BACKEND_PORT:'4305'},
   timeout:30000,reuseExistingServer:false},
 ]
});
