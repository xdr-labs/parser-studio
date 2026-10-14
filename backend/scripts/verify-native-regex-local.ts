/** Bounded named-capture Regex per-project Native proof. Synthetic Cisco-style events only. */
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import type {ParserProject} from '../src/types.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {nativeRecordSha256,prepareNativeProjectVerification} from '../src/native-project-verification.js';
import {createLocalNativeProjectVerifier} from '../src/local-native-project-verifier.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const ruby=process.env['PARSER_NATIVE_RUBY'];
if(!ruby)throw new Error('NATIVE_PROJECT_RUNTIME_PATH');

const pattern=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[\d.]+)/(?<srcport>\d+) \([\d.]+/\d+\) to \w+:(?<dstip>[\d.]+)/(?<dstport>\d+) \([\d.]+/\d+\)$`;
const project:ParserProject={
 schemaRevision:'0.1',projectId:'draft-regex_firewall',revision:1,
 slug:'regex_firewall',vendor:'Synthetic',product:'FTD-like Firewall',sourceCategory:'network',
 receiver:{protocols:['udp','tcp'],port:7512,bindAddress:'127.0.0.1',messageLengthLimit:16384,tcpFraming:'line'},
 extraction:{format:'regex',pattern},
 normalization:{
  msgOriginSource:'regex_firewall',msgClass:'regex_firewall',msgOriginCategory:'network',ignoreValues:['','N/A','-'],
  topFields:{
   srcip:{normalized_name:'srcip',data_type:'ip'},
   dstip:{normalized_name:'dstip',data_type:'ip'},
   protocol:{normalized_name:'protocol',data_type:'string'},
  },
  nsFields:{
   srcport:{normalized_name:'srcport',data_type:'port'},
   dstport:{normalized_name:'dstport',data_type:'port'},
   event_id:{normalized_name:'log.event_id',data_type:'integer'},
  },
  vendorFields:{},
 },
 classification:{defaultIndex:'syslog',rules:[]},
};
const source=[
 'May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111111111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/53500 (81.2.69.144/53500)',
 'May  5 17:51:18 dev01: %FTD-6-302015: Built inbound UDP connection 222222222 for net:10.10.10.11/53501 (81.2.69.144/53501) to fw111:192.168.2.3/53 (81.2.69.144/53)',
].join('\n');
const origin={source:'regex_firewall',category:'network',class:'regex_firewall'};
const expected=[
 {srcip:'10.10.10.10',dstip:'192.168.2.2',protocol:'TCP',srcport:53500,dstport:53500,
  log:{event_id:302013},stellar_log_index:'syslog',msg_origin:origin},
 {srcip:'10.10.10.11',dstip:'192.168.2.3',protocol:'UDP',srcport:53501,dstport:53,
  log:{event_id:302015},stellar_log_index:'syslog',msg_origin:origin},
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
const report=await createLocalNativeProjectVerifier({rubyExecutable:ruby,environment:allowedEnv}).verify(prepared);
if(!report.nativeUserParserVerified||report.targetImportVerified||report.sensorTrafficSent||
 report.rawValuesReturned||report.eventsPassed!==2||report.recordHashMatches!==2||
 report.eventTimeMatches!==2||!report.confAstVerified||!report.parserCallbackVerified)
 throw new Error('NATIVE_REGEX_SYNTHETIC_PROOF_FAILED');
process.stdout.write(JSON.stringify(report)+'\n');
