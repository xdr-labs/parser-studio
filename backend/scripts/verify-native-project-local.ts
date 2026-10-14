/** Fixed public-synthetic end-to-end proof through the local Native adapter. */
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {sampleProject} from '../test/fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {
  nativeRecordSha256,prepareNativeProjectVerification,
} from '../src/native-project-verification.js';
import {createLocalNativeProjectVerifier}
  from '../src/local-native-project-verifier.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const ruby=process.env['PARSER_NATIVE_RUBY'];
if(!ruby)throw new Error('NATIVE_PROJECT_RUNTIME_PATH');

const project=sampleProject();
project.projectId='draft-native_bound';
project.classification.rules=project.classification.rules.filter(r=>r.operator==='equals');
const source=[
 '{"source":{"ip":"192.0.2.10"},"destination":{"ip":"198.51.100.20","port":"443"},"action":"deny","event":{"id":"99"}}',
 '{"source":{"ip":"192.0.2.11"},"destination":{"ip":"198.51.100.21","port":"53"},"action":"allow","event":{"id":"100"}}',
].join('\n');
const origin={source:'sample_firewall',category:'network',class:'sample_firewall'};
const expected=[
 {srcip:'192.0.2.10',dstip:'198.51.100.20',dstport:443,action:'deny',
  log:{event_id:99},stellar_log_index:'threat',msg_origin:origin},
 {srcip:'192.0.2.11',dstip:'198.51.100.21',dstport:53,action:'allow',
  log:{event_id:100},stellar_log_index:'syslog',msg_origin:origin},
];
const prepared=prepareNativeProjectVerification({
 contract:'parser-studio.native-project-request.v0.1',confirmed:true,
 recipe:recipeFromLegacyProject(project,sha(source),2),legacyProject:project,source,
 expected:expected.map((record,index)=>({
  eventId:'event-'+(index+1),recordSha256:nativeRecordSha256(record),eventTimeMs:null,
 })),
});
const allowedEnv:Record<string,string>={BUNDLE_GEMFILE:resolve('Gemfile')};
for(const key of ['BUNDLE_PATH','BUNDLE_FROZEN','GEM_HOME','GEM_PATH','RUBYLIB',
 'LD_LIBRARY_PATH','LANG','LC_ALL','HOME'] as const){
 const value=process.env[key];if(value)allowedEnv[key]=value;
}
const verifier=createLocalNativeProjectVerifier({
 rubyExecutable:ruby,environment:allowedEnv,
});
const report=await verifier.verify(prepared);
if(!report.nativeUserParserVerified||report.targetImportVerified||
   report.sensorTrafficSent||report.rawValuesReturned||
   report.eventsPassed!==2||report.recordHashMatches!==2||
   report.eventTimeMatches!==2)
 throw new Error('NATIVE_PROJECT_SYNTHETIC_PROOF_FAILED');
process.stdout.write(JSON.stringify(report)+'\n');
