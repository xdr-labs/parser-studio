/**
 * Operator/developer CLI for the FIXED PUBLIC SYNTHETIC native qualification
 * archive. Never reads arbitrary file paths, owner fixtures, credentials or
 * customer logs; no target traffic and no automatic parser application.
 *
 * Run from backend/:
 *   node dist/scripts/native-regression.js archive
 *   node dist/scripts/native-regression.js compare <old-head-sha> <new-head-sha>
 */
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {closeSync,constants,fstatSync,lstatSync,openSync,readFileSync} from "node:fs";
import {resolve} from "node:path";
import {TextDecoder} from "node:util";
import {NativeRegressionError,validateSyntheticNativeCaseReport}
  from "../src/native-regression-diff.js";
import {SyntheticNativeRegressionStore} from "../src/native-regression-store.js";

const error=(code:string):never=>{throw new NativeRegressionError(code);};
const sha=(buf:Buffer)=>createHash("sha256").update(buf).digest("hex");
const allowed=/^[0-9a-f]{40}$/;
function readPrivateLocalJson(name:string):unknown{
  const full=resolve(".tmp",name);
  const uid=process.getuid?.();
  const st=lstatSync(full,{throwIfNoEntry:false});
  if(uid===undefined||!st||!st.isFile()||st.isSymbolicLink()||
     st.nlink!==1||st.uid!==uid||(st.mode&0o077)!==0||
     st.size<1||st.size>128*1024)
    return error("REGRESSION_SOURCE_UNSAFE");
  if(typeof constants.O_NOFOLLOW!=="number")error("REGRESSION_SOURCE_UNSAFE");
  let fd=-1;
  try{
    fd=openSync(full,constants.O_RDONLY|constants.O_NOFOLLOW);
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.uid!==uid||opened.nlink!==1||
       (opened.mode&0o077)!==0||opened.size<1||opened.size>128*1024||
       opened.dev!==st.dev||opened.ino!==st.ino)
      error("REGRESSION_SOURCE_UNSAFE");
    const bytes=readFileSync(fd);
    return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
  }catch(e){
    if(e instanceof NativeRegressionError)throw e;
    return error("REGRESSION_SOURCE_UNSAFE");
  }finally{if(fd>=0)closeSync(fd);}
}
function verifiedCurrentCaseReport():{report:ReturnType<
  typeof validateSyntheticNativeCaseReport>;fixtureSha:string}{
  const head=execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim();
  const changed=execFileSync("git",["status","--porcelain"],{encoding:"utf8"}).trim();
  if(!allowed.test(head)||changed)error("REGRESSION_HEAD_NOT_QUALIFIED");
  const current=readPrivateLocalJson("synthetic-native-report.json") as Record<string,unknown>;
  const golden=readPrivateLocalJson("synthetic-golden-report.json") as Record<string,unknown>;
  const report=validateSyntheticNativeCaseReport(
    readPrivateLocalJson("synthetic-golden-cases-report.json"));
  const fixtureBytes=readFileSync(resolve("test_native/fixtures/synthetic-golden.v0.1.json"));
  const fixtureSha=sha(fixtureBytes);
  const fixture=JSON.parse(fixtureBytes.toString("utf8")) as {
    kind?:string;origin?:string;cases?:Array<{id:string;slug:string}>};
  if(current.kind!=="xdr-labs.parser-studio.synthetic-native-profile.v0.1"||
     current.backendHead!==head||current.worktreeDirty!==false||
     current.result!=="SYNTHETIC_FLUENTD_PARSER_AND_CONF_AST_PASS"||
     current.syntheticGoldenCases!==23||current.syntheticGoldenProfiles!==10||
     current.syntheticGoldenCaseReportSha256!==sha(
       readFileSync(resolve(".tmp/synthetic-golden-cases-report.json")))||
     current.actualTdAgentOrStellarImport!==false||
     current.targetImportVerified!==false||current.sensorTrafficSent!==false||
     current.pocApiMutationPerformed!==false||
     golden.kind!=="parser-studio.synthetic-golden-native.v0.1"||
     golden.backendHead!==head||golden.fixtureSha256!==fixtureSha||
     golden.casesPassed!==23||golden.profilesPassed!==10||
     golden.actualTdAgentOrStellarImport!==false||
     golden.targetImportVerified!==false||
     fixture.kind!=="parser-studio.synthetic-golden-events.v0.1"||
     fixture.origin!=="independently-authored-public-synthetic"||
     !Array.isArray(fixture.cases)||fixture.cases.length!==23||
     report.backendHead!==head||report.fixtureSha256!==fixtureSha||
     report.cases.length!==fixture.cases.length||
     report.cases.some((item,i)=>item.id!==fixture.cases![i]?.id||
        item.slug!==fixture.cases![i]?.slug))
    error("REGRESSION_HEAD_NOT_QUALIFIED");
  return {report,fixtureSha};
}
try{
  const argv=process.argv.slice(2);
  const store=new SyntheticNativeRegressionStore(resolve(".tmp/native-regression"));
  if(argv.length===1&&argv[0]==="archive"){
    const {report,fixtureSha}=verifiedCurrentCaseReport();
    const saved=store.archiveVerifiedCaseEvidence(report,fixtureSha);
    process.stdout.write("SYNTHETIC_NATIVE_ARCHIVE_OK head="+saved.backendHead+
      " cases="+saved.cases+" reused="+saved.reused+
      " realTargetVerified=false\n");
  }else if(argv.length===3&&argv[0]==="compare"&&
           allowed.test(argv[1]!)&&allowed.test(argv[2]!)){
    process.stdout.write(JSON.stringify(store.compare(argv[1]!,argv[2]!))+"\n");
  }else{
    error("REGRESSION_ARGUMENTS_INVALID");
  }
}catch(reason){
  process.stderr.write((reason instanceof NativeRegressionError?
    reason.code:"REGRESSION_COMMAND_FAILED")+"\n");
  process.exitCode=2;
}
