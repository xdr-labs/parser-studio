/**
 * Mandatory H2 CI-only validation of a fixed, independently authored,
 * synthetic record corpus in a network-disabled Ruby/Fluentd container.
 * No customer source, public HTTP route, DP access or target import.
 */
import {createHash} from 'node:crypto';
import {sampleProject} from '../test/fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {
 nativeRecordSha256,prepareNativeProjectVerification,
} from '../src/native-project-verification.js';
import {createIsolatedNativeProjectVerifier}
 from '../src/isolated-native-project-verifier.js';

const imageId=process.env['PARSER_NATIVE_ISOLATED_IMAGE_ID'];
if(!imageId)throw new Error('NATIVE_ISOLATION_IMAGE_ID');
const project=sampleProject();
project.projectId='draft-native_bound';
project.classification.rules=project.classification.rules.filter(
 rule=>rule.operator==='equals');
const raw=[
 '{"source":{"ip":"192.0.2.10"},"destination":{"ip":"198.51.100.20","port":"443"},"action":"deny","event":{"id":"99"}}',
 '{"source":{"ip":"192.0.2.11"},"destination":{"ip":"198.51.100.21","port":"53"},"action":"allow","event":{"id":"100"}}',
].join('\n');
const expected=[
 {srcip:'192.0.2.10',dstip:'198.51.100.20',dstport:443,action:'deny',
  log:{event_id:99},stellar_log_index:'threat',
  msg_origin:{source:'sample_firewall',category:'network',class:'sample_firewall'}},
 {srcip:'192.0.2.11',dstip:'198.51.100.21',dstport:53,action:'allow',
  log:{event_id:100},stellar_log_index:'syslog',
  msg_origin:{source:'sample_firewall',category:'network',class:'sample_firewall'}},
];
const hash=(text:string)=>createHash('sha256').update(text,'utf8').digest('hex');
const prepared=prepareNativeProjectVerification({
 contract:'parser-studio.native-project-request.v0.1',
 confirmed:true,
 legacyProject:project,
 recipe:recipeFromLegacyProject(project,hash(raw),2),
 source:raw,
 expected:expected.map((record,index)=>({
  eventId:'event-'+(index+1),
  recordSha256:nativeRecordSha256(record),
  eventTimeMs:null,
 })),
});
const verifier=createIsolatedNativeProjectVerifier({
 dockerExecutable:'/usr/bin/docker',imageId,
});
const report=await verifier.verify(prepared);
if(!report.nativeUserParserVerified||report.targetImportVerified||
 report.sensorTrafficSent||report.rawValuesReturned||
 report.eventCount!==2||report.eventsPassed!==2||
 report.recordHashMatches!==2||report.eventTimeMatches!==2)
 throw new Error('NATIVE_ISOLATION_SYNTHETIC_PROOF_FAILED');
const receipt={
 contract:'parser-studio.isolated-native-evidence.v1',
 scope:'CI_FIXED_PUBLIC_SYNTHETIC_ONLY',
 imageId,
 network:'none',filesystem:'read-only',privileged:false,
 containerUser:'65532:65532',
 resourceProfile:'768m-cpu1-pids64-cpu25-wall35',
 report,
 realUserParserClaim:false,
 fluentdTargetImportClaim:false,
 stellarDpVerified:false,
};
const serialized=JSON.stringify(receipt);
if(serialized.includes(raw)||serialized.includes('"192.0.2.10"')||
 serialized.includes('"198.51.100.20"'))
 throw new Error('NATIVE_ISOLATION_PRIVATE_VALUE_LEAK');
process.stdout.write(serialized+'\n');
