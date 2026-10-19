import {defineConfig,devices} from '@playwright/test';
const port=5197,multiPassPort=4497;
export default defineConfig({
 testDir:'tests',testMatch:['novice-declared-schema-20261019.spec.ts','novice-transport-framing-20261019.spec.ts','novice-parser-readiness-20261019.spec.ts'],
 outputDir:'/tmp/parser-poc-candidate-browser-results-20261019',workers:1,
 reporter:'list',timeout:30000,retries:0,
 use:{baseURL:'http://127.0.0.1:'+port,viewport:{width:1440,height:900},trace:'retain-on-failure'},
 projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}],
 webServer:[
  {command:'python3 runtime/multipass/multipass_preview_api.py --port '+multiPassPort,url:'http://127.0.0.1:'+multiPassPort+'/health',timeout:30000,reuseExistingServer:false},
  {command:'npm run dev -- --port '+port+' --strictPort',url:'http://127.0.0.1:'+port+'/',env:{PARSER_STUDIO_MULTIPASS_PORT:String(multiPassPort),PARSER_STUDIO_BACKEND_PORT:'4305'},timeout:30000,reuseExistingServer:false}
 ]
});
