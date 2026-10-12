import { defineConfig, devices } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const port = Number(process.env.PARSER_STUDIO_TEST_PORT || 5180);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid isolated browser test port');
const liveBackend=process.env.PARSER_STUDIO_LIVE_BACKEND==='1';
const backendPort=Number(process.env.PARSER_STUDIO_BACKEND_PORT || (liveBackend?4191:4179));
if(!Number.isInteger(backendPort)||backendPort<1024||backendPort>65535||backendPort===port)
  throw new Error('Invalid isolated backend port');
const backendRoot=liveBackend?resolve(process.env.PARSER_STUDIO_BACKEND_ROOT||''):null;
if(liveBackend){
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
  env:{PARSER_STUDIO_BACKEND_PORT:String(backendPort)},
  timeout:30_000,reuseExistingServer:false,
};
const webServer=liveBackend
  ? [{
      command:'node '+quote(join(backendRoot!,'dist/src/server.js')),
      url:'http://127.0.0.1:'+backendPort+'/health',
      env:{PARSER_BACKEND_PORT:String(backendPort)},
      timeout:30_000,reuseExistingServer:false,
    },viteServer]
  :viteServer;

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
  webServer,
});
