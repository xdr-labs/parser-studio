/**
 * H2 CI-only Native project verifier. A fixed, built image is referred to by
 * its immutable local sha256 ID and receives exact generated Ruby/conf via
 * stdin. No host mounts, network, privileged device or host process namespace.
 *
 * This is deliberately NOT an HTTP route or a publicly reachable service.
 * Installing it does not enable user parser verification.
 */
import {randomBytes} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {realpath,lstat} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {
 NativeProjectVerificationError,
 verifyNativeProjectReport,
 type NativeProjectPrepared,
 type NativeProjectVerificationReport,
} from './native-project-verification.js';
import {buildNativeProjectRunnerInput,type NativePreparedVerifier}
 from './local-native-project-verifier.js';

const IMAGE_ID=/^sha256:[a-f0-9]{64}$/;
const CONTAINER_NAME=/^parser-h2-[a-f0-9]{20}$/;
const MAX_INPUT=768*1024;
const MAX_OUTPUT=64*1024;
const TIMEOUT_MS=35_000;
const CLI_ENV=Object.freeze({PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp'});

function deny(code:string):never{throw new NativeProjectVerificationError(code);}

/** Kept pure for independent strict negative/positive policy tests. */
export function buildIsolatedNativeDockerArgs(imageId:string,name:string):string[]{
 if(!IMAGE_ID.test(imageId))deny('NATIVE_ISOLATION_IMAGE_ID');
 if(!CONTAINER_NAME.test(name))deny('NATIVE_ISOLATION_CONTAINER_NAME');
 return [
   'run','--rm','--interactive','--name',name,
   '--network','none','--ipc','none','--read-only',
   '--cap-drop','ALL','--security-opt','no-new-privileges',
   '--user','65532:65532','--pids-limit','64',
   '--memory','768m','--cpus','1',
   '--ulimit','cpu=25:25','--ulimit','nofile=64:64',
   '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777',
   '--workdir','/opt/native',
   imageId,
 ];
}

export interface IsolatedNativeOptions{
 dockerExecutable:string;
 imageId:string;
}

/** Only an exact pre-built image ID can be executed. The trusted Ruby fixture
 * validates source/pair hashes and emits a sanitized receipt; raw stderr is
 * discarded. A runtime failure always fails closed.
 */
export function createIsolatedNativeProjectVerifier(
 options:IsolatedNativeOptions,
):NativePreparedVerifier{
 if(!IMAGE_ID.test(options.imageId))deny('NATIVE_ISOLATION_IMAGE_ID');
 return {async verify(prepared:NativeProjectPrepared):Promise<NativeProjectVerificationReport>{
   if(!isAbsolute(options.dockerExecutable))deny('NATIVE_ISOLATION_DOCKER_PATH');
   let docker:string;
   try{
     docker=await realpath(options.dockerExecutable);
     const stat=await lstat(docker);
     if(!stat.isFile()||(stat.mode&0o111)===0)
       deny('NATIVE_ISOLATION_DOCKER_PATH');
   }catch{deny('NATIVE_ISOLATION_DOCKER_PATH');}
   const payload=JSON.stringify(buildNativeProjectRunnerInput(prepared));
   if(Buffer.byteLength(payload,'utf8')>MAX_INPUT)
     deny('NATIVE_ISOLATION_INPUT_LIMIT');
   const name='parser-h2-'+randomBytes(10).toString('hex');
   const args=buildIsolatedNativeDockerArgs(options.imageId,name);
   let output=Buffer.alloc(0),oversize=false,timedOut=false;
   const child=spawn(docker,args,{
     env:CLI_ENV,stdio:['pipe','pipe','pipe'],
     cwd:'/',windowsHide:true,
   });
   child.stdout.on('data',(chunk:Buffer)=>{
     if(oversize)return;
     if(output.byteLength+chunk.byteLength>MAX_OUTPUT){
       oversize=true;child.kill('SIGKILL');return;
     }
     output=Buffer.concat([output,chunk]);
   });
   // The Ruby runner is a potentially hostile execution context; never echo
   // or persist its stderr or pass it to test failure messages.
   child.stderr.on('data',()=>{});
   const finish=new Promise<number>((resolve,reject)=>{
     const timer=setTimeout(()=>{
       timedOut=true;
       child.kill('SIGKILL');
     },TIMEOUT_MS);
     child.once('error',()=>{
       clearTimeout(timer);
       reject(new NativeProjectVerificationError('NATIVE_ISOLATION_DOCKER_UNAVAILABLE'));
     });
     child.once('close',(code)=>{
       clearTimeout(timer);
       resolve(code??-1);
     });
   });
   child.stdin.on('error',()=>{});
   child.stdin.end(payload,'utf8');
   let code:number;
   try{code=await finish;}
   finally{
     if(timedOut||oversize){
       // The Docker CLI can die before its contained process. Stop that exact
       // random-name container, not an unknown host resource.
       spawnSync(docker,['rm','-f',name],{
         env:CLI_ENV,stdio:'ignore',timeout:3000,windowsHide:true,
       });
     }
   }
   if(timedOut)deny('NATIVE_ISOLATION_WALL_TIMEOUT');
   if(oversize)deny('NATIVE_ISOLATION_OUTPUT_LIMIT');
   if(code!==0)deny('NATIVE_ISOLATION_EXECUTION_FAILED');
   let result:unknown;
   try{result=JSON.parse(output.toString('utf8'));}
   catch{deny('NATIVE_ISOLATION_REPORT_INVALID');}
   return verifyNativeProjectReport(result,prepared);
 }};
}
