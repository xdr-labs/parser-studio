/** Fixed public-synthetic input for per-project Native runner qualification. */
import {createHash} from 'node:crypto';
import {sampleProject} from '../test/fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {
  nativeRecordSha256,prepareNativeProjectVerification,
} from '../src/native-project-verification.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
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
const recipe=recipeFromLegacyProject(project,sha(source),2);
const prepared=prepareNativeProjectVerification({
 contract:'parser-studio.native-project-request.v0.1',confirmed:true,
 recipe,legacyProject:project,source,
 expected:expected.map((record,index)=>({
  eventId:'event-'+(index+1),recordSha256:nativeRecordSha256(record),eventTimeMs:null,
 })),
});
const fragment=prepared.files.find(x=>x.name===prepared.parserName)!;
const conf=prepared.files.find(x=>x.name===prepared.confName)!;
process.stdout.write(JSON.stringify({
 contract:'parser-studio.native-project-runner-input.v0.1',
 sourceSha256:prepared.sourceSha256,recipeSha256:prepared.recipeSha256,
 parserName:prepared.parserName,confName:prepared.confName,
 parserSha256:prepared.parserSha256,confSha256:prepared.confSha256,
 receiver:prepared.receiver,parserSource:fragment.content,confSource:conf.content,
 events:prepared.events,
}));
