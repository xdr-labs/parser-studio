/**
 * Exact compiler-generated, non-customer H2 sandbox fixture.
 * Author truth is hard-coded independently of browser/native output.
 * This module NEVER reads CLI-provided logs or projects.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {nativeRecordSha256,prepareNativeProjectVerification}
  from '../src/native-project-verification.js';

export const H2_EVENTS=[
  '{"source":{"ip":"192.0.2.10"},"destination":{"ip":"198.51.100.20","port":"443"},"action":"deny","event":{"id":"99"}}',
  '{"source":{"ip":"192.0.2.11"},"destination":{"ip":"198.51.100.21","port":"53"},"action":"allow","event":{"id":"100"}}',
] as const;
const origin={source:'sample_firewall',category:'network',class:'sample_firewall'};
const H2_EXPECTED=[
 {srcip:'192.0.2.10',dstip:'198.51.100.20',dstport:443,action:'deny',
  log:{event_id:99},stellar_log_index:'threat',msg_origin:origin},
 {srcip:'192.0.2.11',dstip:'198.51.100.21',dstport:53,action:'allow',
  log:{event_id:100},stellar_log_index:'syslog',msg_origin:origin},
] as const;
const sha=(data:string)=>createHash('sha256').update(data,'utf8').digest('hex');

export function prepareH2Synthetic(){
 const project=sampleProject();
 project.projectId='draft-native_h2_synthetic';
 project.classification.rules=project.classification.rules.filter(rule=>rule.operator==='equals');
 const source=H2_EVENTS.join('\n');
 const prepared=prepareNativeProjectVerification({
  contract:'parser-studio.native-project-request.v0.1',
  confirmed:true,
  recipe:recipeFromLegacyProject(project,sha(source),2),
  legacyProject:project,source,
  expected:H2_EXPECTED.map((record,index)=>({
    eventId:'event-'+(index+1),
    recordSha256:nativeRecordSha256(record),
    eventTimeMs:null,
  })),
 });
 assert.equal(prepared.eventCount,2);
 assert.equal(prepared.targetImportVerified,false);
 return prepared;
}
