import { defineConfig, devices } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const port = Number(process.env.PARSER_STUDIO_TEST_PORT || 5180);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid isolated browser test port');
const liveBackend=process.env.PARSER_STUDIO_LIVE_BACKEND==='1';
// Ordinary browser regression must use the same pinned, built loopback compiler
// as the dedicated native/HTTP acceptance suite. Do not silently proxy 4179.
const browserBackend=liveBackend||process.env.PARSER_STUDIO_BROWSER_BACKEND==='1';
const backendPort=Number(process.env.PARSER_STUDIO_BACKEND_PORT || (liveBackend?4191:4179));
if(!Number.isInteger(backendPort)||backendPort<1024||backendPort>65535||backendPort===port)
  throw new Error('Invalid isolated backend port');
const isolatedMultiPass=process.env.PARSER_STUDIO_TEST_MULTIPASS==='1';
const multiPassPort=Number(process.env.PARSER_STUDIO_MULTIPASS_PORT || 4292);
if(!Number.isInteger(multiPassPort)||multiPassPort<1024||multiPassPort>65535||
  multiPassPort===port||multiPassPort===backendPort)
  throw new Error('Invalid isolated Multi-Pass test port');
const multiPassServerFile=resolve('runtime/multipass/multipass_preview_api.py');
if(isolatedMultiPass&&!existsSync(multiPassServerFile))
  throw new Error('Pinned in-repository Multi-Pass service is required for isolated browser tests.');
const backendRoot=browserBackend?resolve(process.env.PARSER_STUDIO_BACKEND_ROOT||''):null;
if(browserBackend){
  if(!process.env.PARSER_STUDIO_BACKEND_ROOT||
    !/^[a-f0-9]{40}$/.test(process.env.PARSER_STUDIO_BACKEND_HEAD||'')||
    !backendRoot||!existsSync(join(backendRoot,'dist/src/server.js')))
    throw new Error('Explicit built, pinned backend checkout is required for integrated Chromium tests.');
  const actual=execFileSync('git',['-C',backendRoot,'rev-parse','HEAD'],
    {encoding:'utf8',timeout:5000}).trim();
  if(actual!==process.env.PARSER_STUDIO_BACKEND_HEAD)
    throw new Error('Integrated backend HEAD does not match the pinned target.');
}
const quote=(s:string)=>"'"+s.replace(/'/g,"'\\''")+"'";
const viteServer={
  command:'npm run dev -- --port '+port+' --strictPort',
  url:'http://127.0.0.1:'+port+'/',
  env:{PARSER_STUDIO_BACKEND_PORT:String(backendPort),PARSER_STUDIO_MULTIPASS_PORT:String(multiPassPort)},
  timeout:30_000,reuseExistingServer:false,
};
const multiPassServer={
  command:'python3 '+quote(multiPassServerFile)+' --port '+multiPassPort,
  url:'http://127.0.0.1:'+multiPassPort+'/health',
  timeout:30_000,reuseExistingServer:false,
};
const webServer=[
  ...(browserBackend?[{
    command:'node '+quote(join(backendRoot!,'dist/src/server.js')),
    url:'http://127.0.0.1:'+backendPort+'/health',
    env:{PARSER_BACKEND_PORT:String(backendPort)},
    timeout:30_000,reuseExistingServer:false,
  }]:[]),
  ...(isolatedMultiPass?[multiPassServer]:[]),
  viteServer,
];

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  // Historical no-longer-exposed Wizard/Workbench tests are retained in Git,
  // NOT counted as current PASS; see tests/legacy-removed-ui/README.md.
  testIgnore: '**/tests/legacy-removed-ui/**',
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
  webServer,
});
