/**
 * Trusted developer CI-only command to project a VERIFIED FIXED synthetic
 * Ruby/Fluentd capability manifest from exact-HEAD local evidence.
 * Does not accept arguments, read private fixtures, run Ruby, or open sockets.
 */
import {createHash,randomBytes} from "node:crypto";
import {execFileSync} from "node:child_process";
import {
  closeSync,constants,existsSync,fsyncSync,fstatSync,lstatSync,openSync,
  readFileSync,realpathSync,renameSync,unlinkSync,writeSync,
} from "node:fs";
import {resolve} from "node:path";
import {TextDecoder} from "node:util";
import {buildSyntheticNativeCapabilityManifest,NativeCapabilityManifestError}
  from "../src/native-capability-manifest.js";

const deny=(code:string):never=>{throw new NativeCapabilityManifestError(code);};
const sha=(bytes:Buffer)=>createHash("sha256").update(bytes).digest("hex");
const root=resolve(".tmp");
const uid=process.getuid?.();
function trustedRoot(){
  const info=lstatSync(root,{throwIfNoEntry:false});
  if(uid===undefined||!info||!info.isDirectory()||
     info.isSymbolicLink()||info.uid!==uid||(info.mode&0o002)!==0||
     realpathSync(root)!==root)
    deny("NATIVE_CAPABILITY_DIRECTORY_UNSAFE");
  if(typeof constants.O_NOFOLLOW!=="number")
    deny("NATIVE_CAPABILITY_NOFOLLOW_UNAVAILABLE");
}
function fixedFile(name:string,maxSize=128*1024):Buffer{
  const path=resolve(root,name);
  const info=lstatSync(path,{throwIfNoEntry:false});
  if(!info||!info.isFile()||info.isSymbolicLink()||info.nlink!==1||
     info.uid!==uid||(info.mode&0o077)!==0||
     info.size<1||info.size>maxSize)
    throw new NativeCapabilityManifestError("NATIVE_CAPABILITY_FILE_UNSAFE");
  let fd=-1;
  try{
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==uid||
       (opened.mode&0o077)!==0||
       opened.size<1||opened.size>maxSize||
       opened.ino!==info.ino||opened.dev!==info.dev)
      deny("NATIVE_CAPABILITY_FILE_UNSAFE");
    return readFileSync(fd);
  }catch(error){
    if(error instanceof NativeCapabilityManifestError)throw error;
    return deny("NATIVE_CAPABILITY_FILE_UNSAFE");
  }finally{if(fd>=0)closeSync(fd);}
}
function parse(bytes:Buffer):unknown{
  try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
  catch{return deny("NATIVE_CAPABILITY_FILE_UNSAFE");}
}
function save(report:unknown){
  const target=resolve(root,"synthetic-native-capabilities.json");
  const old=lstatSync(target,{throwIfNoEntry:false});
  if(old&&(!old.isFile()||old.isSymbolicLink()||
    old.uid!==uid||old.nlink!==1||(old.mode&0o077)!==0))
    deny("NATIVE_CAPABILITY_FILE_UNSAFE");
  const bytes=Buffer.from(JSON.stringify(report,null,2)+"\n","utf8");
  if(bytes.length>128*1024)deny("NATIVE_CAPABILITY_FILE_UNSAFE");
  const stage=resolve(root,".native-capability-"+randomBytes(12).toString("hex")+".tmp");
  let fd=-1;
  try{
    fd=openSync(stage,constants.O_WRONLY|constants.O_CREAT|
      constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    const info=fstatSync(fd);
    if(!info.isFile()||info.uid!==uid||info.nlink!==1||
       (info.mode&0o077)!==0)
      deny("NATIVE_CAPABILITY_FILE_UNSAFE");
    if(writeSync(fd,bytes)!==bytes.length)
      deny("NATIVE_CAPABILITY_FILE_UNSAFE");
    fsyncSync(fd);closeSync(fd);fd=-1;
    trustedRoot();
    renameSync(stage,target);
    const rootFd=openSync(root,constants.O_RDONLY|constants.O_NOFOLLOW);
    try{fsyncSync(rootFd);}finally{closeSync(rootFd);}
  }catch(error){
    if(error instanceof NativeCapabilityManifestError)throw error;
    return deny("NATIVE_CAPABILITY_FILE_UNSAFE");
  }finally{
    if(fd>=0)closeSync(fd);
    if(existsSync(stage))unlinkSync(stage);
  }
}
try{
  if(process.argv.length!==2)deny("NATIVE_CAPABILITY_ARGUMENTS_INVALID");
  trustedRoot();
  const head=execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim();
  const dirty=execFileSync("git",["status","--porcelain"],{encoding:"utf8"}).trim();
  if(dirty||!/^[0-9a-f]{40}$/.test(head))
    deny("NATIVE_CAPABILITY_HEAD_UNQUALIFIED");
  const fixtureBytes=readFileSync(resolve(
    "test_native/fixtures/synthetic-golden.v0.1.json"));
  const fixedFixture=parse(fixtureBytes) as {kind?:string;origin?:string;
    cases?:Array<{id?:string;slug?:string}>};
  if(fixedFixture.kind!=="parser-studio.synthetic-golden-events.v0.1"||
     fixedFixture.origin!=="independently-authored-public-synthetic"||
     !Array.isArray(fixedFixture.cases))
    throw new NativeCapabilityManifestError("NATIVE_CAPABILITY_FIXTURE_INVALID");
  const caseEvidenceBytes=fixedFile("synthetic-golden-cases-report.json");
  const report=buildSyntheticNativeCapabilityManifest({
    nativeReport:parse(fixedFile("synthetic-native-report.json")),
    goldenReport:parse(fixedFile("synthetic-golden-report.json")),
    caseReport:parse(caseEvidenceBytes),
    caseEvidenceBytes,
    expectedHead:head,
    expectedFixtureSha256:sha(fixtureBytes),
    expectedCases:fixedFixture.cases.map(value=>({id:value.id,slug:value.slug})),
  });
  save(report);
  process.stdout.write("NATIVE_SYNTHETIC_CAPABILITIES_PASS head="+head+
    " profiles="+report.profiles.length+" cases="+report.casesPassed+
    " digest="+report.digest+" stellarImport=false sensor=false\n");
}catch(error){
  process.stderr.write((error instanceof NativeCapabilityManifestError?
    error.code:"NATIVE_CAPABILITY_COMMAND_FAILED")+"\n");
  process.exitCode=2;
}
