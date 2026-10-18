/**
 * Offline-only synthetic native regression report store.
 * Single operator/qualification writer, 0700 directory, 0600 immutable
 * per-HEAD evidence files; reads only hashes/statuses from reviewed synthetics.
 * Never imports customer source logs, sample values, live target data, or
 * credentials. A same-UID or privileged hostile host is out of scope.
 */
import {constants,closeSync,existsSync,fsyncSync,fstatSync,lstatSync,
  mkdirSync,openSync,readFileSync,readdirSync,writeSync} from "node:fs";
import {basename,isAbsolute,join} from "node:path";
import {TextDecoder} from "node:util";
import {compareSyntheticNativeCaseReports,NativeRegressionError,
  validateSyntheticNativeCaseReport,type NativeCaseEvidence} from "./native-regression-diff.js";

const GIT_HEAD=/^[0-9a-f]{40}$/;
const SHA=/^[0-9a-f]{64}$/;
const MAX_REPORT=128*1024;
const MAX_REPORTS=64;
const denied=(code:string):never=>{throw new NativeRegressionError(code);};
const uid=()=>process.getuid?.();
export class SyntheticNativeRegressionStore{
  readonly #root:string;
  constructor(absoluteRoot:string){
    if(typeof absoluteRoot!=="string"||!isAbsolute(absoluteRoot)||
      basename(absoluteRoot)!=="native-regression"||
      absoluteRoot.includes("/../")||absoluteRoot.includes("/./")||
      uid()===undefined||typeof constants.O_NOFOLLOW!=="number")
      denied("REGRESSION_STORAGE_UNSUPPORTED");
    this.#root=absoluteRoot;
  }
  #dir(create:boolean):void{
    const rootStat=lstatSync(this.#root,{throwIfNoEntry:false});
    if(!rootStat&&create){
      try{mkdirSync(this.#root,{mode:0o700});}
      catch{return denied("REGRESSION_DIRECTORY_UNSAFE");}
    }
    const st=lstatSync(this.#root,{throwIfNoEntry:false});
    if(!st||!st.isDirectory()||st.isSymbolicLink()||st.uid!==uid()||
      (st.mode&0o077)!==0)
      denied("REGRESSION_DIRECTORY_UNSAFE");
  }
  #file(head:string):string{
    if(!GIT_HEAD.test(head))denied("REGRESSION_HEAD_INVALID");
    return join(this.#root,head+".json");
  }
  #openReport(head:string):NativeCaseEvidence{
    this.#dir(false);
    const file=this.#file(head);
    const st=lstatSync(file,{throwIfNoEntry:false});
    if(!st)return denied("REGRESSION_NOT_FOUND");
    if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.uid!==uid()||
      (st.mode&0o077)!==0||st.size<1||st.size>MAX_REPORT)
      denied("REGRESSION_FILE_UNSAFE");
    let fd=-1;
    try{
      fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);
      const info=fstatSync(fd);
      if(!info.isFile()||info.nlink!==1||info.uid!==uid()||
        (info.mode&0o077)!==0||info.size<1||info.size>MAX_REPORT||
        info.dev!==st.dev||info.ino!==st.ino)
        denied("REGRESSION_FILE_UNSAFE");
      const bytes=readFileSync(fd);
      const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const report=validateSyntheticNativeCaseReport(JSON.parse(text));
      if(report.backendHead!==head)denied("REGRESSION_REPORT_INVALID");
      return report;
    }catch(error){
      if(error instanceof NativeRegressionError)throw error;
      return denied("REGRESSION_FILE_UNSAFE");
    }finally{if(fd>=0)closeSync(fd);}
  }
  archiveVerifiedCaseEvidence(input:unknown,expectedFixtureSha256:string):{
    backendHead:string;cases:number;reused:boolean;
  }{
    const report=validateSyntheticNativeCaseReport(input);
    if(!SHA.test(expectedFixtureSha256)||
       report.fixtureSha256!==expectedFixtureSha256||
       report.cases.some(row=>row.status!=="PASS"))
      denied("REGRESSION_UNQUALIFIED");
    this.#dir(true);
    const target=this.#file(report.backendHead);
    const existing=lstatSync(target,{throwIfNoEntry:false});
    if(existing){
      const old=this.#openReport(report.backendHead);
      if(JSON.stringify(old)!==JSON.stringify(report))
        denied("REGRESSION_ARCHIVE_CONFLICT");
      return {backendHead:report.backendHead,cases:report.cases.length,reused:true};
    }
    const entries=readdirSync(this.#root);
    if(entries.length>=MAX_REPORTS||
      entries.some(name=>!GIT_HEAD.test(name.replace(/\.json$/,""))||!name.endsWith(".json")))
      denied("REGRESSION_CAPACITY_REACHED");
    const bytes=Buffer.from(JSON.stringify(report)+"\n","utf8");
    if(bytes.length>MAX_REPORT)denied("REGRESSION_CAPACITY_REACHED");
    let fd=-1;
    try{
      fd=openSync(target,constants.O_WRONLY|constants.O_CREAT|
        constants.O_EXCL|constants.O_NOFOLLOW,0o600);
      const stat=fstatSync(fd);
      if(!stat.isFile()||stat.uid!==uid()||stat.nlink!==1||
        (stat.mode&0o077)!==0)denied("REGRESSION_FILE_UNSAFE");
      if(writeSync(fd,bytes)!==bytes.length)denied("REGRESSION_FILE_UNSAFE");
      fsyncSync(fd);
      const dirFd=openSync(this.#root,constants.O_RDONLY|constants.O_NOFOLLOW);
      try{fsyncSync(dirFd);}finally{closeSync(dirFd);}
      return {backendHead:report.backendHead,cases:report.cases.length,reused:false};
    }catch(err){
      if(err instanceof NativeRegressionError)throw err;
      return denied("REGRESSION_ARCHIVE_FAILED");
    }finally{if(fd>=0)closeSync(fd);}
  }
  compare(baselineHead:string,candidateHead:string){
    return compareSyntheticNativeCaseReports(
      this.#openReport(baselineHead),this.#openReport(candidateHead));
  }
}
