/**
 * Disabled-by-default local adapter for the source-bound Native verifier.
 *
 * The HTTP server never constructs this automatically. A trusted deployment
 * must explicitly provide the Ruby executable/runtime environment and inject
 * the returned verifier behind its own authorization callback.
 */
import {spawn} from 'node:child_process';
import {lstat,realpath} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  NativeProjectVerificationError,
  type NativeProjectPrepared,
  type NativeProjectVerificationReport,
  verifyNativeProjectReport,
} from './native-project-verification.js';

const MAX_STDIN_BYTES=768*1024;
const MAX_STDOUT_BYTES=64*1024;
const DEFAULT_WALL_MS=25_000;
const DEFAULT_RUNNER=fileURLToPath(
  new URL('../test_native/project_native_runner.rb',import.meta.url),
);

export interface LocalNativeProjectVerifierOptions{
  rubyExecutable:string;
  /** Defaults to the package-owned fixed runner. */
  runnerScript?:string;
  /** Linux prlimit path. Defaults to /usr/bin/prlimit. */
  resourceLimiter?:string;
  /** Minimal explicitly supplied runtime environment. No process.env merge. */
  environment?:Record<string,string>;
  wallTimeoutMs?:number;
}
export interface NativePreparedVerifier{
  verify(prepared:NativeProjectPrepared):Promise<NativeProjectVerificationReport>;
}

function fail(code:string):never{throw new NativeProjectVerificationError(code);}

async function trustedRegular(path:string,executable=false):Promise<string>{
  if(!isAbsolute(path))fail('NATIVE_PROJECT_RUNTIME_PATH');
  let real:string,stat;
  try{
    real=await realpath(path);stat=await lstat(real);
  }catch{fail('NATIVE_PROJECT_RUNTIME_PATH');}
  if(!stat.isFile()||stat.nlink!==1||(executable&&(stat.mode&0o111)===0))
    fail('NATIVE_PROJECT_RUNTIME_PATH');
  return real;
}

export function buildNativeProjectRunnerInput(prepared:NativeProjectPrepared):unknown{
  if(prepared.contract!=='parser-studio.native-project-prepared.v0.1'||
     prepared.nativeUserParserVerified!==false||prepared.targetImportVerified!==false||
     prepared.files.length!==2||prepared.events.length!==prepared.eventCount)
    fail('NATIVE_PROJECT_PREPARED_UNTRUSTED');
  const fragment=prepared.files.find(x=>x.name===prepared.parserName);
  const conf=prepared.files.find(x=>x.name===prepared.confName);
  if(!fragment||!conf)fail('NATIVE_PROJECT_PREPARED_UNTRUSTED');
  return {
    contract:'parser-studio.native-project-runner-input.v0.1',
    sourceSha256:prepared.sourceSha256,recipeSha256:prepared.recipeSha256,
    parserName:prepared.parserName,confName:prepared.confName,
    parserSha256:prepared.parserSha256,confSha256:prepared.confSha256,
    receiver:{port:prepared.receiver.port,protocols:[...prepared.receiver.protocols]},
    parserSource:fragment.content,confSource:conf.content,
    events:prepared.events.map(event=>({...event})),
  };
}

export function createLocalNativeProjectVerifier(
 options:LocalNativeProjectVerifierOptions,
):NativePreparedVerifier{
 const timeout=options.wallTimeoutMs??DEFAULT_WALL_MS;
 if(!Number.isSafeInteger(timeout)||timeout<1_000||timeout>30_000)
   fail('NATIVE_PROJECT_RUNTIME_LIMIT');
 return {async verify(prepared){
   const [ruby,runner,limiter]=await Promise.all([
     trustedRegular(options.rubyExecutable,true),
     trustedRegular(options.runnerScript??DEFAULT_RUNNER,false),
     trustedRegular(options.resourceLimiter??'/usr/bin/prlimit',true),
   ]);
   const payload=JSON.stringify(buildNativeProjectRunnerInput(prepared));
   if(Buffer.byteLength(payload,'utf8')>MAX_STDIN_BYTES)
     fail('NATIVE_PROJECT_RUNNER_INPUT_LIMIT');
   const env:NodeJS.ProcessEnv={};
   for(const [key,value] of Object.entries(options.environment??{})){
     if(!/^(?:BUNDLE_GEMFILE|BUNDLE_PATH|BUNDLE_FROZEN|GEM_HOME|GEM_PATH|RUBYLIB|LD_LIBRARY_PATH|LANG|LC_ALL|HOME)$/.test(key)||
        typeof value!=='string'||value.includes('\u0000'))
       fail('NATIVE_PROJECT_RUNTIME_ENV');
     env[key]=value;
   }
   const child=spawn(limiter,[
     '--as=1073741824','--cpu=30','--',
     ruby,'-rbundler/setup',runner,
   ],{stdio:['pipe','pipe','pipe'],env});
   let stdout=Buffer.alloc(0),overflow=false,settled=false;
   child.stdout.on('data',(chunk:Buffer)=>{
     if(overflow)return;
     stdout=Buffer.concat([stdout,chunk]);
     if(stdout.length>MAX_STDOUT_BYTES){overflow=true;child.kill('SIGKILL');}
   });
   // Consume but never propagate Ruby/library stderr: it could contain source-adjacent text.
   child.stderr.on('data',()=>{});
   const result=new Promise<unknown>((resolve,reject)=>{
     const timer=setTimeout(()=>{
       if(!settled){child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),500).unref();}
     },timeout);
     child.once('error',()=>{clearTimeout(timer);settled=true;reject(
       new NativeProjectVerificationError('NATIVE_PROJECT_RUNNER_UNAVAILABLE'));});
     child.once('close',code=>{
       clearTimeout(timer);settled=true;
       if(code!==0||overflow){reject(new NativeProjectVerificationError(
         overflow?'NATIVE_PROJECT_RUNNER_OUTPUT_LIMIT':'NATIVE_PROJECT_RUNNER_FAILED'));return;}
       try{resolve(JSON.parse(stdout.toString('utf8')));}
       catch{reject(new NativeProjectVerificationError('NATIVE_PROJECT_RUNNER_REPORT_INVALID'));}
     });
   });
   child.stdin.on('error',()=>{});
   child.stdin.end(payload,'utf8');
   return verifyNativeProjectReport(await result,prepared);
 }};
}
