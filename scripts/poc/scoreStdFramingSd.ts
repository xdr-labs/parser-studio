/** Standards-derived RFC6587/5424 transport and SD controls against
 * existing unmodified browser and source-byte implementations.
 * Synthetic source cases are not independent manufacturer holdout events.
 */
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {splitSyslogStream} from '../../src/syslogFraming';
import {rfc5424SdByteEscapes} from '../../src/poc/rfc5424SdByteEscapes';
import {parseRfc5424Subset} from '../../src/rfc5424Subset';

const SOURCE='15f3d48772dc7b05ee0807c6801d6771efbcf454003feed9f8b2e9b74fed1b7d';
const full=path.join(path.dirname(fileURLToPath(import.meta.url)),
 'standardsFramingSdCases.pinned.json');
const bytes=fs.readFileSync(full);
if(createHash('sha256').update(bytes).digest('hex')!==SOURCE)
 throw Error('Frozen normative transport+structured-data source controls drifted');
type TCase={id:string;kind:'stream'|'sd';wire:string;valid:boolean;records?:number;
 elements?:number;param?:{id:string;name:string;decoded:string}[]};
const corpus=JSON.parse(bytes.toString('utf8')) as {cases:TCase[];source:string};
const counts={standardsDerivedCases:0,streamCases:0,sdCases:0,passed:0,
 mismatch:0,transportBoundaryMismatch:0,sdSourceValueMismatch:0,
 sdBrowserSubsetGap:0,rawByteDrift:0,autoNativeSuccess:0};
const details:Array<{id:string;scope:string;expectedValid:boolean;sourceValid:boolean;
 browserValid?:boolean;status:'MATCH'|'MISMATCH'}>=[];
for(const test of corpus.cases){
 counts.standardsDerivedCases++;
 const original=Buffer.from(test.wire,'utf8');
 let sourceValid:boolean,pass=false,browserValid:undefined|boolean;
 if(test.kind==='stream'){
  counts.streamCases++;
  const result=splitSyslogStream(test.wire);
  sourceValid=result.ok;
  pass=sourceValid===test.valid&&
    (!test.valid||(result.ok&&result.records.length===test.records));
  if(result.ok){
    const counted=result.mode==='rfc6587_octet_counting_stream';
    const reconstructed=counted?
      result.records.map(row=>String(Buffer.byteLength(row,'utf8'))+' '+row).join(''):
      undefined;
    // Exact byte concatenation is only expected under valid OCTET-COUNTING.
    if(counted&&pass){
      counts.rawByteDrift+=Number(reconstructed!==test.wire);
    }
    if(test.valid&&result.records.length!==test.records)
      counts.transportBoundaryMismatch++;
  }
 }else{
  counts.sdCases++;
  const reference=rfc5424SdByteEscapes(original);
  const browser=parseRfc5424Subset(test.wire);
  sourceValid=reference!==null;browserValid=browser.ok;
  pass=sourceValid===test.valid;
  if(reference){
    const observed=reference.elements.flatMap(e=>e.params.map(p=>({
      id:p.sdId,name:p.name,decoded:p.decodedValue,start:p.rawValueStart,end:p.rawValueEnd,
    })));
    if(test.valid){
      const expected=test.param??[];
      pass&&=reference.elements.length===test.elements&&observed.length===expected.length;
      for(let i=0;i<expected.length;i++){
        const actual=observed[i]!,gold=expected[i]!;
        if(!actual||actual.id!==gold.id||actual.name!==gold.name||
           actual.decoded!==gold.decoded){
          pass=false;counts.sdSourceValueMismatch++;continue;
        }
        try{
          new TextDecoder('utf8',{fatal:true})
           .decode(original.subarray(actual.start,actual.end));
        }catch{pass=false;counts.rawByteDrift++;}
      }
      counts.rawByteDrift+=Number(reference.sourceBytes!==original.length||
       reference.canAutoPromote||reference.nativeTarget!=='NOT_VERIFIED');
      if(!browser.ok&&pass)counts.sdBrowserSubsetGap++;
    }
  }
 }
 counts.passed+=Number(pass);counts.mismatch+=Number(!pass);
 details.push({id:test.id,scope:test.kind,expectedValid:test.valid,
    sourceValid,browserValid,status:pass?'MATCH':'MISMATCH'});
}
const output={
 schema:'P0_STD_FRAMING_SD_PARTIAL_CONFORMANCE_NO_NATIVE_CERTIFICATION',
 frozenSourceSha256:SOURCE,
 normativeCaseNature:'AUTHORED_SYNTHETIC_NOT_FRESH_BLIND_HOLDOUT',
 counts,details,fullEventFP:'UNSCORABLE',
 declaredVendorEscapeDecoded:false,
 productBackendTouched:false,
 valuePrinting:false,
};
console.log('P0_STD_RFC6587_5424_TRANSFER '+JSON.stringify(output));
if(counts.standardsDerivedCases!==21||counts.mismatch||counts.rawByteDrift||
 counts.sdSourceValueMismatch||counts.transportBoundaryMismatch)process.exitCode=1;
