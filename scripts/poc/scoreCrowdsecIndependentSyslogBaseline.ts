/** Independently frozen third-party author-expected partial source fields.
 * Never relabel partial asserted fields as full/native/manufacturer success. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
import {arbitrateSourceBody} from '../../src/poc/boundedSourceBodyArbiter';
const home=path.join(os.homedir(),'.local/state/parserstudio-new-independent-security-20261017');
const digest=(b:Buffer)=>crypto.createHash('sha256').update(b).digest('hex');
const blob=fs.readFileSync(path.join(home,'crowdsec-independent-raw-stage-expected.v1.json'));
const ORACLE='e147d816e5ff88f46476d3716e6fe61b10e48852eaa99b025cc0e83ec0d07dee';
if(digest(blob)!==ORACLE)throw Error('Independent source goldens drifted');
type Expected={canonical_field:string;value:string;startByte:number;endByte:number};
type Row={raw:string;source_file:string;status:string;fields:Expected[]};
const all=JSON.parse(blob.toString('utf8')) as Row[];
const grouped=new Map<string,{events:number;scorable:number;expected:number;hit:number;missing:number;
 conflicting:number;bodyReview:number;headerReview:number;rawOnly:number;unsupported:number;byteDrift:number;}>();
const create=()=>({events:0,scorable:0,expected:0,hit:0,missing:0,
 conflicting:0,bodyReview:0,headerReview:0,rawOnly:0,unsupported:0,byteDrift:0});
for(const row of all){
 const stats=grouped.get(row.source_file)??create();
 grouped.set(row.source_file,stats);
 stats.events++;
 const syslog=inspectGeneralSyslogEnvelope(row.raw);
 const body=arbitrateSourceBody(row.raw);
 stats.bodyReview+=Number(body.disposition==='REVIEW_ONLY_STRUCTURED_BODY');
 stats.headerReview+=Number(body.disposition==='REVIEW_ONLY_ENVELOPE');
 stats.rawOnly+=Number(body.disposition==='RAW_ONLY');
 stats.unsupported+=Number(syslog.disposition==='ABSTAIN_UNSAFE');
 stats.byteDrift+=Number(syslog.originalRaw!==row.raw||syslog.sourceBytes!==Buffer.byteLength(row.raw,'utf8'));
 if(row.status!=='PARTIAL_SCORABLE')continue;
 stats.scorable++;
 for(const original of row.fields){
  stats.expected++;
  const actual=syslog.fields.filter(x=>x.name===original.canonical_field);
  if(actual.some(x=>x.value===original.value&&
      x.startByte===original.startByte&&x.endByte===original.endByte))stats.hit++;
  else{
   stats.missing++;
   if(actual.length)stats.conflicting++;
  }
 }
}
const totals=create();
const report=Object.fromEntries([...grouped.entries()].map(([p,x])=>{
 for(const k of Object.keys(totals) as Array<keyof typeof totals>)totals[k]+=x[k];
 return [p,x];
}));
console.log('CROWDSEC_PUBLISHER_RAW_STAGE_PARTIAL_BASELINE '+JSON.stringify({
 evidence:{publisher:'crowdsecurity/hub',upstreamRevision:'46df77d6739c41b4e808ef572188f950ba84fecd',
 oracleSha256:ORACLE},
 totals,byUpstreamFile:report,
 falsePositiveScore:'UNSCORABLE_INCOMPLETE_AUTHOR_FIELDS',
 manufacturerEscapeSemantics:'NOT_CERTIFIED',
 fullEventNativeEquivalence:'NOT_VERIFIED',
 sealedBeforeCandidateEvaluation:true,rawOrAuthorExpectedValuesPrinted:false,
}));
if(totals.events!==17||totals.expected!==27||totals.byteDrift)process.exitCode=1;
