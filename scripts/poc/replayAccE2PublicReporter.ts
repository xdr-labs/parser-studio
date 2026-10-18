/**
 * Private, source-only recheck of a public syslog-ng issue's displayed text.
 * Never logs or commits raw reporter message content; never certifies packets.
 */
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {reviewPairedRelaySourceBytes} from '../../src/poc/accE2RelayPairByteFidelity';

const sha=(bytes:Uint8Array)=>
  createHash('sha256').update(bytes).digest('hex');
const expected={
  report:'18607e16472b1adbe8cfb2f84f8a73890ccab7c744390b7cb51f27e17ace8b71',
  source:'8f7959d0ead7d6061a1cbef928194debf757f5cd91c451e4c1b6f6dd53507ef4',
  normal:'e1a9dca6b66842166c7b4e1e59be463f7834744bd00893fcbedb5aa2b9ac64be',
  spoof:'d045dc2215f3ad70970eb304e70456e9ad4fde25ad3f5283ac27b63c3b9a0cfd',
} as const;
const dir=join(homedir(),'.local/state/parserstudio-acc-e2-syslogng-reporter-20261018');
const report=new TextEncoder().encode(readFileSync(join(dir,'reporter-issue-body.txt'),'utf8'));
if(sha(report)!==expected.report)throw new Error('Pinned public reporter issue text changed');
const pair=JSON.parse(readFileSync(join(dir,'reporter-observed-messages.json'),'utf8')) as {
  sourceType:string;
  producer_message:string;
  receiver_without_spoof:string;
  receiver_with_spoof:string;
};
if(pair.sourceType!=='THIRD_PARTY_REPORTER_DISPLAYED_TEXT_NOT_RAW_WIRE')
  throw new Error('Reporter source type was not explicitly qualified');
const encode=(s:string)=>new TextEncoder().encode(s);
const upstream=encode(pair.producer_message);
if(sha(upstream)!==expected.source)throw new Error('Public source text checksum changed');
const observations=[
  {label:'without_spoof',raw:pair.receiver_without_spoof,
    expectedSha:expected.normal,disposition:'REVIEW_ONLY_COLLECTOR_APPEND_ONLY',
    commonPrefixBytes:1045,missing:null,added:{startByte:1045,endByte:1046}},
  {label:'with_spoof',raw:pair.receiver_with_spoof,
    expectedSha:expected.spoof,disposition:'REVIEW_ONLY_COLLECTOR_STRICT_PREFIX',
    commonPrefixBytes:921,missing:{startByte:921,endByte:1045},added:null},
] as const;
const summaries=[];
for(const row of observations){
  const received=encode(row.raw);
  if(sha(received)!==row.expectedSha)throw new Error(row.label+': pinned message changed');
  const reviewed=reviewPairedRelaySourceBytes({
    upstreamBytes:upstream,upstreamSha256:expected.source,
    collectorBytes:received,collectorSha256:row.expectedSha,
  });
  if(reviewed.disposition!==row.disposition||
     reviewed.commonPrefixBytes!==row.commonPrefixBytes||
     JSON.stringify(reviewed.lostUpstreamTail)!==JSON.stringify(row.missing)||
     JSON.stringify(reviewed.addedCollectorTail)!==JSON.stringify(row.added)||
     reviewed.canAutoPromote!==false||
     reviewed.originalDeviceIdentity!=='NOT_ATTESTED'||
     reviewed.sourceComplete!==false)
    throw new Error(row.label+': reporter stage review differs from frozen expectations');
  summaries.push({label:row.label,
    sourceBytes:reviewed.upstreamBytes,collectorBytes:reviewed.collectorBytes,
    disposition:reviewed.disposition,commonPrefixBytes:reviewed.commonPrefixBytes,
    missingTail:reviewed.lostUpstreamTail,addedTail:reviewed.addedCollectorTail,
    originalDeviceAttested:false,manufacturerFieldOracleEligible:false});
}
process.stdout.write(JSON.stringify({
  classification:'THIRD_PARTY_REPORTER_DISPLAYED_TEXT_NOT_RAW_WIRE',
  publicIssue:'https://github.com/syslog-ng/syslog-ng/issues/2532',
  exactTextPairReplays:summaries.length,observations:summaries,
  manufacturerWireAccuracyDenominator:0,
},null,2)+'\n');
